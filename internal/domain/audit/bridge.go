package audit

import (
	"context"
	"encoding/json"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// SetChainBridge wires the tamper-proof chain into the audit service so that
// allowlisted events (auth/session/token/consent, pii_view) are also recorded in
// the hash chain — additive to the legacy mxid_audit_log write. Optional: unset =
// legacy-only (bridgeToChain is a no-op).
func (s *Service) SetChainBridge(db *gorm.DB, c *Capturer) {
	s.chainDB = db
	s.chainCapturer = c
}

// bridgeToChain records an allowlisted event into the tamper-proof chain. It runs
// post-hoc in the async audit handler, so a failure is logged, never propagated
// (the originating action already committed). No-op when unwired or not allowlisted.
func (s *Service) bridgeToChain(ctx context.Context, log *AuditLog) {
	if s.chainCapturer == nil || s.chainDB == nil {
		return
	}
	class, ok := chainClassForEvent(log.EventType)
	if !ok {
		return
	}
	// Actor comes from the ENRICHED AuditLog (authoritative), stamped into ctx so
	// Capturer.Capture attributes the chain row correctly regardless of the ctx the
	// async handler carried.
	actor := auditctx.Actor{ActorType: log.ActorType, TenantID: log.TenantID}
	if log.ActorID != nil {
		actor.ActorID = *log.ActorID
	}
	if log.ActorName != nil {
		// Currently unused: AuditPending has no actor_name column, so
		// Capturer.Capture never persists this. Kept for forward compat /
		// if the chain schema grows an actor_name field.
		actor.ActorName = *log.ActorName
	}
	if log.IP != nil {
		actor.IP = *log.IP
	}
	if log.UserAgent != nil {
		actor.UserAgent = *log.UserAgent
	}
	if log.SessionID != nil {
		actor.SessionID = *log.SessionID
	}
	detail := map[string]any{"event_status": log.EventStatus}
	if len(log.Detail) > 0 {
		var d map[string]any
		if err := json.Unmarshal(log.Detail, &d); err == nil {
			for k, v := range redactMap(d) {
				if k != "event_status" { // don't let payload clobber the status we set
					detail[k] = v
				}
			}
		}
	}
	ev := Event{ChainClass: class, EventType: log.EventType, Detail: detail}
	if log.ResourceType != nil {
		ev.ResourceType = *log.ResourceType
	}
	if log.ResourceID != nil {
		ev.ResourceID = *log.ResourceID
	}
	// The originating HTTP request ctx is frequently already canceled by the
	// time the async audit handler runs this (event.Bus dispatches detached
	// from the request lifecycle). Detach cancellation but keep values (e.g.
	// auditctx) alive for Capture's tx.WithContext — same hazard the legacy
	// repo.Create / nameResolver paths in this package already guard against.
	writeCtx := context.WithoutCancel(ctx)
	if err := s.chainCapturer.Capture(auditctx.With(writeCtx, actor), s.chainDB, ev); err != nil {
		// Like the legacy-write-failure marker: a dropped chain write is a
		// security-relevant gap, but the action already happened — log + alert.
		s.logger.Error("audit chain bridge failed",
			zap.String("marker", "audit_chain_bridge_failed"),
			zap.Bool("alert", true),
			zap.String("event_type", log.EventType),
			zap.Error(err))
	}
}
