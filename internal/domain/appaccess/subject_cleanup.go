package appaccess

import (
	"context"

	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/domain/permission"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// SetLogger injects a logger for the background event handlers. Optional: nil
// leaves the handlers silent (used by unit embeddings that build a bare
// Service). Wired in app.Run alongside the event bus.
func (s *Service) SetLogger(l *zap.Logger) { s.logger = l }

// SubscribeEvents wires policy cleanup to subject-deletion domain events. When a
// group / org / role that a policy points at is deleted, its rules would
// otherwise dangle: the console renders the subject as "(unknown)" and the row
// survives as a phantom allow/deny that can silently affect future access
// decisions. Removing them on delete keeps the policy table referentially clean
// (there is no DB-level FK cascade — subject_id is an application reference).
//
// Safe to call on a nil bus (Subscribe is a no-op there).
func (s *Service) SubscribeEvents() {
	if s.eventBus == nil {
		return
	}
	s.eventBus.Subscribe(event.GroupDeleted, s.cleanupSubject(SubjectGroup, "id"))
	s.eventBus.Subscribe(event.OrgDeleted, s.cleanupSubject(SubjectOrg, "id"))
	s.eventBus.Subscribe(permission.RoleDeleted, s.cleanupSubject(SubjectRole, "role_id"))
}

// cleanupSubject returns a handler that deletes every policy whose subject is
// the just-deleted entity. idKey is the payload key carrying the entity id
// (group/org use "id", role uses "role_id"). Runs asynchronously on the bus, so
// it builds a fresh cross-tenant context rather than trusting the originating
// request's (possibly cancelled) one; matching on the globally-unique subject_id
// makes the cross-tenant delete precise.
func (s *Service) cleanupSubject(subjectType, idKey string) event.Handler {
	return func(_ context.Context, evt event.Event) {
		id := payloadInt64(evt.Payload, idKey)
		if id == 0 {
			return
		}
		ctx := tenantscope.WithCrossTenant(context.Background())
		n, err := s.repo.DeleteBySubject(ctx, subjectType, id)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("appaccess: cleanup policies for deleted subject failed",
					zap.String("subject_type", subjectType), zap.Int64("subject_id", id), zap.Error(err))
			}
			return
		}
		if n > 0 {
			// Nudge connected portals to re-fetch: a user's app list may have
			// changed now that an inherited rule is gone.
			s.eventBus.Publish(ctx, event.Event{Type: EventAccessPolicyChanged, Payload: map[string]any{
				"subject_type": subjectType, "subject_id": id, "removed": n,
			}})
			if s.logger != nil {
				s.logger.Info("appaccess: removed orphaned policies for deleted subject",
					zap.String("subject_type", subjectType), zap.Int64("subject_id", id), zap.Int64("removed", n))
			}
		}
	}
}

// payloadInt64 pulls an int64 id out of an event payload, tolerating the two
// shapes producers use: map[string]any and map[string]int64.
func payloadInt64(payload any, key string) int64 {
	switch p := payload.(type) {
	case map[string]int64:
		return p[key]
	case map[string]any:
		switch v := p[key].(type) {
		case int64:
			return v
		case int:
			return int64(v)
		case float64:
			return int64(v)
		}
	}
	return 0
}
