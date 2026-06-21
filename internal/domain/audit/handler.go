package audit

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/pagination"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// Handler handles HTTP requests for the audit domain.
type Handler struct {
	svc      *Service
	tenantID int64
}

// NewHandler creates a new audit handler.
func NewHandler(svc *Service, tenantID int64) *Handler {
	return &Handler{svc: svc, tenantID: tenantID}
}

// RegisterRoutes registers audit routes on the given router group.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	audit := rg.Group("/audit")
	{
		audit.GET("/logs", authz.Require("audit.read", nil), h.List)
		audit.GET("/stats", authz.Require("audit.read", nil), h.GetStats)
	}
}

// List handles GET /audit/logs.
func (h *Handler) List(c *gin.Context) {
	p := pagination.Parse(c)

	var req ListAuditRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}

	params := ListParams{
		TenantID:     tenantctx.FromContext(c, h.tenantID),
		Page:         p.Page,
		PageSize:     p.PageSize,
		EventType:    req.EventType,
		ActorID:      req.ActorID,
		ResourceType: req.ResourceType,
		HideAPI:      req.HideAPI,
	}

	// Parse optional time range
	if req.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, req.StartTime); err == nil {
			params.StartTime = &t
		}
	}
	if req.EndTime != "" {
		if t, err := time.Parse(time.RFC3339, req.EndTime); err == nil {
			params.EndTime = &t
		}
	}

	logs, total, err := h.svc.List(c.Request.Context(), params)
	if err != nil {
		response.InternalError(c, "failed to list audit logs")
		return
	}

	items := make([]*AuditLogResponse, len(logs))
	for i, l := range logs {
		items[i] = toResponse(l)
	}

	response.Paginated(c, items, total, p.Page, p.PageSize)
}

// GetStats handles GET /audit/stats.
func (h *Handler) GetStats(c *gin.Context) {
	// Default to today
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	end := now

	if s := c.Query("start_time"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			start = t
		}
	}
	if e := c.Query("end_time"); e != "" {
		if t, err := time.Parse(time.RFC3339, e); err == nil {
			end = t
		}
	}

	stats, err := h.svc.GetStats(c.Request.Context(), tenantctx.FromContext(c, h.tenantID), start, end)
	if err != nil {
		response.InternalError(c, "failed to get audit stats")
		return
	}

	response.OK(c, stats)
}

// toResponse converts an AuditLog model to an AuditLogResponse DTO.
func toResponse(l *AuditLog) *AuditLogResponse {
	resp := &AuditLogResponse{
		ID:           l.ID,
		TenantID:     l.TenantID,
		ActorID:      l.ActorID,
		ActorName:    l.ActorName,
		ActorType:    l.ActorType,
		EventType:    l.EventType,
		EventStatus:  l.EventStatus,
		ResourceType: l.ResourceType,
		ResourceID:   l.ResourceID,
		ResourceName: l.ResourceName,
		IP:           l.IP,
		UserAgent:    l.UserAgent,
		GeoCity:      l.GeoCity,
		GeoCountry:   l.GeoCountry,
		SessionID:    l.SessionID,
		CreatedAt:    l.CreatedAt,
	}

	// Unmarshal detail JSON into map
	if len(l.Detail) > 0 {
		var detail map[string]any
		if err := json.Unmarshal(l.Detail, &detail); err == nil {
			resp.Detail = detail
		}
	}

	return resp
}
