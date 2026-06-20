package offboarding

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/response"
)

// Handler exposes the offboarding console API.
type Handler struct {
	svc *Service
}

// NewHandler creates the offboarding HTTP handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes mounts the offboard action under the shared /users group.
// Gated by user.update — offboarding is a user-management write. The action is
// high-risk (cuts all access for a person) and is audited via user.offboarded.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("/users/:id/offboard", authz.Require("user.update", nil), h.Offboard)
}

// Offboard handles POST /users/:id/offboard — one-click access cutoff for a
// departing user (disable account + kill all sessions).
func (h *Handler) Offboard(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid user id")
		return
	}
	if err := h.svc.Offboard(c.Request.Context(), id); err != nil {
		response.InternalError(c, "offboard failed")
		return
	}
	response.OK(c, gin.H{"offboarded": true})
}
