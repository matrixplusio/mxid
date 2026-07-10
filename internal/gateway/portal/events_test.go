package portal

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/event"
	"go.uber.org/zap"
)

// A membership change (admin adds/removes a user from a role/group/org that an
// app-access policy targets) changes the user's portal app list, so it must push
// an apps_updated SSE frame. Before this wiring only app_access.changed (policy
// edits) did, leaving the list stale after membership edits.
func TestAttachBusSubscribers_MembershipEventsPushAppsUpdated(t *testing.T) {
	bus := event.NewBus(zap.NewNop())
	AttachBusSubscribers(bus, nil, zap.NewNop()) // rdb nil → emit straight to local broker

	cases := []string{
		"role.member_added", "role.member_removed",
		"group.member_added", "group.member_removed",
		"org.member_added", "org.member_removed",
	}
	for _, evType := range cases {
		t.Run(evType, func(t *testing.T) {
			ch := sseBroker.subscribe()
			defer sseBroker.unsubscribe(ch)

			bus.Publish(context.Background(), event.Event{Type: evType, Payload: map[string]any{"user_id": int64(7)}})

			select {
			case got := <-ch:
				if got.Type != "apps_updated" {
					t.Fatalf("%s should emit apps_updated, got %q", evType, got.Type)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s did not push an SSE frame", evType)
			}
		})
	}
}

// A role permission-catalog change does NOT affect app visibility (AppsForUser
// never reads mxid_role_permission), so it must NOT spam an apps_updated push.
func TestAttachBusSubscribers_RolePermissionsSetDoesNotPush(t *testing.T) {
	bus := event.NewBus(zap.NewNop())
	AttachBusSubscribers(bus, nil, zap.NewNop())

	ch := sseBroker.subscribe()
	defer sseBroker.unsubscribe(ch)

	bus.Publish(context.Background(), event.Event{Type: "role.permissions_set", Payload: map[string]any{"role_id": int64(1)}})

	select {
	case got := <-ch:
		t.Fatalf("role.permissions_set must not push an SSE frame, got %q", got.Type)
	case <-time.After(300 * time.Millisecond):
		// no frame — correct.
	}
}
