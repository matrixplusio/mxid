package audit

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// auditedPrefixes are the first-party API surfaces whose state-changing
// requests are captured by the catch-all middleware. Protocol (OIDC/SAML/CAS)
// and bearer-auth OpenAPI traffic is excluded — those emit their own
// domain/token events and aren't operator actions.
var auditedPrefixes = []string{"/api/v1/console", "/api/v1/portal"}

// apiAuditSkip are paths whose rich domain events already cover the action;
// recording a generic api.* row on top would only duplicate the trail.
var apiAuditSkip = []string{
	"/auth/login", "/auth/logout", "/auth/mfa", // login.* / logout events
	"/events", // SSE stream, not a mutation
}

// RecordAPIRequest writes the catch-all audit row for a finished request. It is
// the safety net behind the semantic domain events: every state-changing
// (non-GET) first-party API call is logged with who (actor from auditctx),
// from where (IP / UA), when, what (method + path) and the result (HTTP
// status). A route that forgets to publish a domain event is therefore still
// on the trail, and so is every future route.
//
// Call it AFTER c.Next() from a global middleware so the auth middleware has
// already stamped the actor and the response status is final.
func (s *Service) RecordAPIRequest(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return
	}

	path := c.Request.URL.Path
	if !hasAnyPrefix(path, auditedPrefixes) {
		return
	}
	for _, skip := range apiAuditSkip {
		if strings.Contains(path, skip) {
			return
		}
	}

	status := c.Writer.Status()
	eventStatus := EventStatusSuccess
	if status >= http.StatusBadRequest {
		eventStatus = EventStatusFail
	}

	rt := "api"
	resource := c.Request.Method + " " + path
	detail, _ := json.Marshal(map[string]any{
		"method": c.Request.Method,
		"path":   path,
		"route":  c.FullPath(), // matched route pattern, e.g. /users/:id
		"status": status,
	})

	ip := c.ClientIP()
	ua := c.Request.UserAgent()
	log := &AuditLog{
		ID:           s.idGen.Generate(),
		EventType:    "api." + strings.ToLower(c.Request.Method),
		EventStatus:  eventStatus,
		ResourceType: &rt,
		ResourceName: &resource,
		Detail:       detail,
		IP:           &ip,
		UserAgent:    strPtr(ua),
		CreatedAt:    time.Now(),
	}

	// Best-effort resource_id: the catch-all can't know the domain, but a
	// route's primary `:id` path param (the parent resource — e.g. the app in
	// /apps/:id and /apps/:id/access) is enough to make the row joinable
	// instead of an anonymous PUT. The richer domain event still carries the
	// authoritative subject; this only stops the safety-net row from being
	// blank.
	if idStr := c.Param("id"); idStr != "" {
		if id, err := strconv.ParseInt(idStr, 10, 64); err == nil {
			log.ResourceID = &id
		}
	}

	// Actor identity + tenant are filled by enrich() from the request-scoped
	// auditctx; IP/UA are taken from the live request above so even an
	// unauthenticated mutation (no actor) still records its origin.
	s.createLog(c.Request.Context(), log)
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
