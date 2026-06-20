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

// UserLookup resolves minimal identity (username + tenant) for audit
// labelling, so the trail names who was offboarded rather than a bare id.
type UserLookup interface {
	Lookup(ctx context.Context, userID int64) (username string, tenantID int64, err error)
}

// Service performs the one-click offboard.
type Service struct {
	disabler UserDisabler
	sessions SessionKiller
	lookup   UserLookup
	eventBus *event.Bus
	logger   *zap.Logger
}

// NewService wires the offboarding orchestrator.
func NewService(disabler UserDisabler, sessions SessionKiller, lookup UserLookup, eventBus *event.Bus, logger *zap.Logger) *Service {
	return &Service{disabler: disabler, sessions: sessions, lookup: lookup, eventBus: eventBus, logger: logger}
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
// offboard — it is logged instead. Emits user.offboarded for the audit trail.
func (s *Service) Offboard(ctx context.Context, userID int64) error {
	if err := s.disabler.Disable(ctx, userID); err != nil {
		return fmt.Errorf("disable user: %w", err)
	}

	killed, err := s.sessions.KillAllByUser(ctx, userID)
	if err != nil {
		s.logger.Warn("offboard: kill sessions failed (account already disabled)",
			zap.Int64("user_id", userID), zap.Error(err))
	}

	username, tenantID, _ := s.lookup.Lookup(ctx, userID)
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
