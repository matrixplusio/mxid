package dashboard

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// Handler serves the console dashboard endpoints.
type Handler struct {
	svc      *Service
	tenantID int64
}

// NewHandler creates a dashboard handler. defaultTenantID is the fallback when
// the request carries no tenant context.
func NewHandler(svc *Service, defaultTenantID int64) *Handler {
	return &Handler{svc: svc, tenantID: defaultTenantID}
}

// RegisterRoutes mounts the dashboard routes.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	// Read-only admin overview + audit export. Gated so a bare authenticated
	// console session can't scrape tenant-wide stats or stream the audit log
	// without the corresponding read permission (super_admin passes via `*`).
	d := rg.Group("/dashboard")
	{
		d.GET("/overview", authz.Require("user.read", nil), h.Overview)
		d.GET("/export", authz.Require("audit.read", nil), h.Export)
	}
}

// Overview handles GET /dashboard/overview?range=7|30&tenant_id=<id>.
//
// range selects the metric window in days (default 7, capped at 90). tenant_id
// is an optional super-admin drilldown override; absent it uses the caller's
// tenant context.
func (h *Handler) Overview(c *gin.Context) {
	rangeDays := 7
	if r := c.Query("range"); r != "" {
		if n, err := strconv.Atoi(r); err == nil && n > 0 {
			rangeDays = n
		}
	}
	if rangeDays > 90 {
		rangeDays = 90
	}

	ov, err := h.svc.Overview(c.Request.Context(), h.resolveTenant(c), rangeDays)
	if err != nil {
		response.InternalError(c, "failed to build dashboard overview", err)
		return
	}
	response.OK(c, ov)
}

// Export handles GET /dashboard/export?range=7 — streams the range's audit log
// as CSV for offline analysis / compliance archival (Tier 3).
func (h *Handler) Export(c *gin.Context) {
	rangeDays := 7
	if r := c.Query("range"); r != "" {
		if n, err := strconv.Atoi(r); err == nil && n > 0 {
			rangeDays = n
		}
	}
	if rangeDays > 365 {
		rangeDays = 365
	}
	since := time.Now().AddDate(0, 0, -rangeDays)

	rows, err := h.svc.ExportAudit(c.Request.Context(), h.resolveTenant(c), since)
	if err != nil {
		response.InternalError(c, "failed to export audit log", err)
		return
	}

	filename := fmt.Sprintf("mxid-audit-%s.csv", time.Now().Format("20060102"))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	// Excel-friendly UTF-8 BOM so Chinese actor names render correctly.
	_, _ = c.Writer.WriteString("\xEF\xBB\xBF")

	w := csv.NewWriter(c.Writer)
	defer w.Flush()
	_ = w.Write([]string{"time", "event_type", "status", "actor", "resource_type", "resource_id", "ip", "country"})
	for _, r := range rows {
		_ = w.Write([]string{
			r.CreatedAt.Format(time.RFC3339),
			r.EventType,
			statusLabel(r.EventStatus),
			deref(r.ActorName),
			deref(r.ResourceType),
			resourceIDStr(r.ResourceID),
			deref(r.IP),
			deref(r.GeoCountry),
		})
	}
	c.Status(http.StatusOK)
}

// resolveTenant returns the tenant to scope metrics to: the explicit
// ?tenant_id override (super-admin drilldown) when present and valid,
// otherwise the caller's tenant context.
func (h *Handler) resolveTenant(c *gin.Context) int64 {
	if t := c.Query("tenant_id"); t != "" {
		if id, err := strconv.ParseInt(t, 10, 64); err == nil && id > 0 {
			return id
		}
	}
	return tenantctx.FromContext(c, h.tenantID)
}

func statusLabel(s int) string {
	if s == 1 {
		return "success"
	}
	return "fail"
}

func resourceIDStr(id *int64) string {
	if id == nil {
		return ""
	}
	return itoa(*id)
}
