package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// portalEventsChannel is the Redis pub/sub channel used to fan SSE broker
// events out to every replica. See AttachBusSubscribers.
const portalEventsChannel = "portal:events"

// SSE event channel for the portal. Pushes notifications when admin
// actions invalidate the user's view — e.g. access policy mutated,
// tenant updated — so the UI can re-fetch without the user reloading.
//
// One connection per portal tab. Lifetime tied to the HTTP request;
// EventSource on the browser auto-reconnects on disconnect.
//
// Event types emitted by this endpoint (client switches on SSE `event:`):
//   apps_updated     — re-fetch /apps list
//   tenants_updated  — re-fetch /tenants list
//   ping             — heartbeat every 25s to keep proxies open
type eventsHandler struct {
	bus *event.Bus
}

// global broadcaster — single set of channels that the bus subscribers
// fan events out to. Per-SSE-connection channels register themselves
// here on connect and unregister on disconnect.
var sseBroker = newBroker()

// brokerEvent is what the bus subscribers push into SSE connections.
type brokerEvent struct {
	Type    string `json:"type"`
	Payload any    `json:"payload,omitempty"`
}

type broker struct {
	subs map[chan brokerEvent]struct{}
	add  chan chan brokerEvent
	del  chan chan brokerEvent
	pub  chan brokerEvent
}

func newBroker() *broker {
	b := &broker{
		subs: map[chan brokerEvent]struct{}{},
		add:  make(chan chan brokerEvent),
		del:  make(chan chan brokerEvent),
		pub:  make(chan brokerEvent, 64),
	}
	go b.run()
	return b
}

func (b *broker) run() {
	for {
		select {
		case ch := <-b.add:
			b.subs[ch] = struct{}{}
		case ch := <-b.del:
			delete(b.subs, ch)
			close(ch)
		case ev := <-b.pub:
			for ch := range b.subs {
				select {
				case ch <- ev:
				default:
					// Slow subscriber — drop instead of stalling broker.
				}
			}
		}
	}
}

func (b *broker) subscribe() chan brokerEvent {
	ch := make(chan brokerEvent, 32)
	b.add <- ch
	return ch
}

func (b *broker) unsubscribe(ch chan brokerEvent) {
	b.del <- ch
}

// AttachBusSubscribers wires the in-process event bus to the SSE broker. When
// rdb is non-nil, bus events are published to Redis and fanned out on EVERY
// replica (so a client connected to any pod sees events triggered on any other
// pod); the local broker then receives them via startBrokerRedisSubscriber.
// When rdb is nil, events are pushed straight to the local broker (dev/tests).
func AttachBusSubscribers(bus *event.Bus, rdb *redis.Client, logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}
	emit := func(ev brokerEvent) {
		if rdb != nil {
			// Local delivery is contingent on this Redis round-trip (to avoid
			// double delivery), so a publish/marshal failure drops the event on
			// EVERY pod including this one — log it rather than swallow silently.
			data, err := json.Marshal(ev)
			if err != nil {
				logger.Warn("portal SSE: marshal event failed", zap.String("type", ev.Type), zap.Error(err))
				return
			}
			if err := rdb.Publish(context.Background(), portalEventsChannel, data).Err(); err != nil {
				logger.Warn("portal SSE: publish event failed", zap.String("type", ev.Type), zap.Error(err))
			}
			return // fanned back in via the Redis subscriber — do not also push locally (avoids double delivery)
		}
		sseBroker.pub <- ev
	}
	bus.Subscribe("app_access.changed", func(ctx context.Context, e event.Event) {
		emit(brokerEvent{Type: "apps_updated", Payload: e.Payload})
	})
	// The portal app list is a function of app-access POLICIES *and* the
	// role/group/org MEMBERSHIP those policies match on (AppsForUser resolves a
	// role/group/org-subject policy against the user's bindings). app_access.changed
	// covers policy edits; these six cover the membership side, which otherwise
	// left a user's app list stale until a manual refresh after an admin added or
	// removed them from a role/group/org that grants app access. (role
	// permission-catalog changes are intentionally NOT here — app visibility never
	// reads mxid_role_permission.) These are manual admin ops (dynamic-group sync
	// writes members at the repo layer without emitting per-user events), so the
	// broadcast is low-frequency. Broadcast-all like app_access.changed; each
	// client re-fetches /apps.
	for _, membershipEvent := range []string{
		"role.member_added", "role.member_removed",
		"group.member_added", "group.member_removed",
		"org.member_added", "org.member_removed",
	} {
		bus.Subscribe(membershipEvent, func(ctx context.Context, e event.Event) {
			emit(brokerEvent{Type: "apps_updated", Payload: e.Payload})
		})
	}
	bus.Subscribe("tenant.updated", func(ctx context.Context, e event.Event) {
		emit(brokerEvent{Type: "tenants_updated"})
	})
	bus.Subscribe("tenant.deleted", func(ctx context.Context, e event.Event) {
		emit(brokerEvent{Type: "tenants_updated"})
	})
	if rdb != nil {
		startBrokerRedisSubscriber(rdb, logger)
	}
}

// startBrokerRedisSubscriber fans Redis portal:events messages into the local
// SSE broker. Runs on context.Background(): the SSE broker (newBroker's run
// goroutine) is itself an unmanaged process-lifetime singleton, so this
// mirrors that lifecycle rather than threading a ctx through the 14-param
// Register.
func startBrokerRedisSubscriber(rdb *redis.Client, logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}
	sub := rdb.Subscribe(context.Background(), portalEventsChannel)
	go func() {
		defer sub.Close()
		ch := sub.Channel()
		for msg := range ch {
			var ev brokerEvent
			if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
				logger.Warn("portal SSE: decode broadcast event failed", zap.Error(err))
				continue
			}
			sseBroker.pub <- ev
		}
	}()
}

func registerEventsRoutes(rg *gin.RouterGroup, h *eventsHandler) {
	rg.GET("/events", h.stream)
}

func (h *eventsHandler) stream(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	ch := sseBroker.subscribe()
	defer sseBroker.unsubscribe(ch)

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(200)
	c.Writer.Flush()

	writeSSE(c, "hello", map[string]any{"user_id": strconv.FormatInt(userID, 10)})

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	ctx := c.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !writeSSE(c, "ping", nil) {
				return
			}
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if !writeSSE(c, ev.Type, ev.Payload) {
				return
			}
		}
	}
}

func writeSSE(c *gin.Context, eventName string, payload any) bool {
	w := c.Writer
	if _, err := fmt.Fprintf(w, "event: %s\n", eventName); err != nil {
		return false
	}
	if payload != nil {
		bs, _ := json.Marshal(payload)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", string(bs)); err != nil {
			return false
		}
	} else {
		if _, err := fmt.Fprint(w, "data: {}\n\n"); err != nil {
			return false
		}
	}
	w.Flush()
	return true
}
