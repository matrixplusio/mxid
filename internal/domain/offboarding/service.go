// Package offboarding orchestrates the access-revocation actions taken when an
// employee leaves. This is the L1 ("SSO access cutoff") slice: everything here
// is fully within MXID's control and reuses existing capabilities — no
// downstream provisioning credentials required.
//
// L1 = disable the account (blocks new SSO logins AND the OIDC refresh grant)
// + kill every active session across all namespaces. Together that revokes a
// departing user's access to every app they reach through MXID SSO.
//
// Later slices (outbox-backed delivery, L2 SCIM deprovisioning, L3 offboarding
// report + webhook) build on this seam; see docs/PHASE1-DESIGN.md.
package offboarding

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// UserDisabler sets a user's account status to disabled. Injected so the
// offboarding domain does not import the user domain directly.
type UserDisabler interface {
	Disable(ctx context.Context, userID int64) error
}

// SessionKiller terminates every active session for a user across all session
// namespaces (console / portal / protocol) and reports how many were removed.
type SessionKiller interface {
	KillAllByUser(ctx context.Context, userID int64) (int, error)
}

// UserLookup resolves minimal identity (username + email + tenant) for audit
// labelling and downstream-account matching (SCIM deprovision matches by email).
type UserLookup interface {
	Lookup(ctx context.Context, userID int64) (username, email string, tenantID int64, err error)
}

// ScimKind is the outbox message kind for L2 downstream-account deprovisioning.
// The handler lives ONLY in the EE binary (license-gated scim); CE enqueues it
// only for apps whose provisioning is enabled AND whose SCIM connector is built
// into the running binary, so a CE binary never produces an orphan message.
const ScimKind = "offboarding.scim"

// DeprovisionEnqueuer durably queues a downstream-account deprovision (L2).
// Optional — nil skips it. Enqueue rides the outbox so it survives a crash.
type DeprovisionEnqueuer interface {
	Enqueue(ctx context.Context, tenantID, appID, userID int64, username, email string) error
}

// LogoutNotifier proactively notifies the apps a user is logged into to drop
// their session (OIDC back-channel logout). Optional — nil skips the step.
// Called BEFORE sessions are killed, since the notification targets are
// derived from the user's still-live SSO sessions.
type LogoutNotifier interface {
	NotifyLogout(ctx context.Context, userID int64)
}

// WebhookKind is the outbox message kind for offboarding webhook deliveries.
const WebhookKind = "offboarding.webhook"

// AppRef is one app in a user's footprint, denormalized into a review item so
// the checklist survives later renames/deletes of the app.
type AppRef struct {
	ID   int64  `json:"id,string"`
	Name string `json:"name"`
	Code string `json:"code"`
	Tier string `json:"tier"`
}

// WebhookPayload is the body delivered to a customer's IT/HR system when a user
// is offboarded — enough for them to open work orders for the apps MXID's SSO
// cutoff can't reach.
type WebhookPayload struct {
	TaskID   int64    `json:"task_id,string"`
	UserID   int64    `json:"user_id,string"`
	Username string   `json:"username"`
	Apps     []AppRef `json:"apps"`
}

// WebhookDispatcher gates + durably queues the offboarding webhook. Optional —
// nil (or disabled) skips it. Enqueue rides the transactional outbox so the
// notification survives a crash.
type WebhookDispatcher interface {
	Enabled(ctx context.Context, tenantID int64) bool
	Enqueue(ctx context.Context, tenantID int64, payload WebhookPayload) error
}

// AppFootprint returns the apps a user could reach, to seed the offboarding
// review checklist. Optional — nil produces a task with no items.
type AppFootprint interface {
	ForUser(ctx context.Context, userID, tenantID int64) ([]AppRef, error)
}

// Service performs the one-click offboard.
type Service struct {
	disabler  UserDisabler
	sessions  SessionKiller
	lookup    UserLookup
	logout    LogoutNotifier
	footprint AppFootprint
	repo      Repository
	idGen       *snowflake.Generator
	webhook     WebhookDispatcher
	deprovision DeprovisionEnqueuer
	eventBus    *event.Bus
	logger      *zap.Logger
}

// SetDeprovisionEnqueuer wires the optional L2 downstream-deprovision enqueuer
// (set after construction so the constructor stays stable).
func (s *Service) SetDeprovisionEnqueuer(d DeprovisionEnqueuer) { s.deprovision = d }

// SetWebhookDispatcher wires the optional offboarding webhook (set after
// construction so the long constructor stays stable).
func (s *Service) SetWebhookDispatcher(d WebhookDispatcher) { s.webhook = d }

// NewService wires the offboarding orchestrator. logout / footprint / repo /
// idGen may be nil — the offboard still disables + kills sessions, it just
// skips notification and/or the review-checklist record.
func NewService(disabler UserDisabler, sessions SessionKiller, lookup UserLookup, logout LogoutNotifier, footprint AppFootprint, repo Repository, idGen *snowflake.Generator, eventBus *event.Bus, logger *zap.Logger) *Service {
	return &Service{disabler: disabler, sessions: sessions, lookup: lookup, logout: logout, footprint: footprint, repo: repo, idGen: idGen, eventBus: eventBus, logger: logger}
}

// ListTasks / ListItems / MarkItemDone expose the review trail to the console.
func (s *Service) ListTasks(ctx context.Context, tenantID int64, limit, offset int) ([]*Task, int64, error) {
	if s.repo == nil {
		return nil, 0, nil
	}
	return s.repo.ListTasks(ctx, tenantID, limit, offset)
}

// ListItems returns a task's review items.
func (s *Service) ListItems(ctx context.Context, tenantID, taskID int64) ([]*Item, error) {
	if s.repo == nil {
		return nil, nil
	}
	return s.repo.ListItems(ctx, tenantID, taskID)
}

// MarkItemDone ticks off one app in the review checklist.
func (s *Service) MarkItemDone(ctx context.Context, tenantID, itemID, actorID int64) error {
	if s.repo == nil {
		return nil
	}
	_, err := s.repo.MarkItemDone(ctx, tenantID, itemID, actorID)
	return err
}

// Offboard performs the L1 access cutoff for a departing user as one admin
// action:
//
//  1. Disable the account — the hard gate. Blocks every future SSO login and
//     (via the refresh-grant status check) stops live refresh tokens from
//     minting new access tokens.
//  2. Kill all active sessions across console/portal/protocol so any
//     currently-open session is dropped immediately.
//
// Session kill is best-effort: the account is already disabled (the
// security-critical step), so a session-store hiccup must not fail the
// offboard — it is logged instead. After the cutoff it records a review task
// listing every app the user could reach, so an admin has a checklist to
// confirm downstream cleanup. Emits user.offboarded for the audit trail.
//
// actorID is the admin performing the offboard (for created_by / audit).
func (s *Service) Offboard(ctx context.Context, userID, actorID int64) error {
	if err := s.disabler.Disable(ctx, userID); err != nil {
		return fmt.Errorf("disable user: %w", err)
	}

	// Notify participating apps to drop the user's session BEFORE killing the
	// MXID sessions — the notification targets are derived from the live SSO
	// sessions. Best-effort; never blocks or fails the offboard.
	if s.logout != nil {
		s.logout.NotifyLogout(ctx, userID)
	}

	killed, err := s.sessions.KillAllByUser(ctx, userID)
	if err != nil {
		s.logger.Warn("offboard: kill sessions failed (account already disabled)",
			zap.Int64("user_id", userID), zap.Error(err))
	}

	username, email, tenantID, _ := s.lookup.Lookup(ctx, userID)

	// Record the review checklist: one item per app in the user's footprint.
	// Best-effort — a record-write failure must not undo the access cutoff,
	// which already happened. Logged so the missing checklist is visible.
	if s.repo != nil && s.idGen != nil {
		task := &Task{
			ID:             s.idGen.Generate(),
			TenantID:       tenantID,
			UserID:         userID,
			Username:       username,
			Status:         TaskStatusOpen,
			SessionsKilled: killed,
		}
		if actorID > 0 {
			task.CreatedBy = &actorID
		}
		var items []*Item
		var refs []AppRef
		if s.footprint != nil {
			fps, ferr := s.footprint.ForUser(ctx, userID, tenantID)
			if ferr != nil {
				s.logger.Warn("offboard: compute app footprint failed",
					zap.Int64("user_id", userID), zap.Error(ferr))
			}
			for _, r := range fps {
				if r.Tier == "" {
					r.Tier = TierL1
				}
				refs = append(refs, r)
				items = append(items, &Item{
					ID:       s.idGen.Generate(),
					TaskID:   task.ID,
					TenantID: tenantID,
					AppID:    r.ID,
					AppName:  r.Name,
					AppCode:  r.Code,
					Tier:     r.Tier,
					Status:   ItemStatusPending,
				})
			}
		}
		task.ItemCount = len(items)
		if len(items) == 0 {
			task.Status = TaskStatusResolved // nothing to review
		}
		if cerr := s.repo.CreateTaskWithItems(ctx, task, items); cerr != nil {
			s.logger.Warn("offboard: write review task failed",
				zap.Int64("user_id", userID), zap.Error(cerr))
		} else {
			if s.webhook != nil && s.webhook.Enabled(ctx, tenantID) {
				// Durable webhook to the customer's IT/HR system. Rides the
				// outbox, so it survives a crash and retries. Enqueued only after
				// the task is written so a delivery always has a matching record.
				if werr := s.webhook.Enqueue(ctx, tenantID, WebhookPayload{
					TaskID:   task.ID,
					UserID:   userID,
					Username: username,
					Apps:     refs,
				}); werr != nil {
					s.logger.Warn("offboard: enqueue webhook failed",
						zap.Int64("user_id", userID), zap.Error(werr))
				}
			}
			// L2: for every app the footprint classified as needing a downstream
			// deprovision (provisioning enabled + SCIM connector built in),
			// enqueue a durable deprovision job. The handler is EE-only; CE marks
			// no item L2, so this loop is inert in a CE binary.
			if s.deprovision != nil {
				for _, r := range refs {
					if r.Tier != TierL2 {
						continue
					}
					if derr := s.deprovision.Enqueue(ctx, tenantID, r.ID, userID, username, email); derr != nil {
						s.logger.Warn("offboard: enqueue deprovision failed",
							zap.Int64("user_id", userID), zap.Int64("app_id", r.ID), zap.Error(derr))
					}
				}
			}
		}
	}

	s.eventBus.Publish(ctx, event.Event{
		Type: event.UserOffboarded,
		Payload: map[string]any{
			"user_id":         userID,
			"tenant_id":       tenantID,
			"username":        username,
			"sessions_killed": killed,
		},
	})
	return nil
}
