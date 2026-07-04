package portal

import (
	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/response"
)

// UpdateProfileRequest is the request body for profile update.
//
// Email is intentionally writable here even though verification is not yet
// implemented — setting it must precede sending a verification mail later.
// Email becomes `verified=false` on change (to be enforced once the
// verification flow ships). For now we just persist what the user enters.
type UpdateProfileRequest struct {
	DisplayName string `json:"display_name"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
}

// UpdateAvatarRequest is the request body for avatar update. Avatar is an inline
// base64 data URL; cap ~5 MB of chars (the client crops to a small square PNG,
// and a raw 3 MB image → ~4 M base64 chars still fits) so an oversized payload
// is rejected up front.
type UpdateAvatarRequest struct {
	Avatar string `json:"avatar" binding:"required,max=5242880"`
}

// ProfileHandler serves portal profile endpoints.
type ProfileHandler struct {
	userQuerier UserQuerier
	bus         *event.Bus
}

// NewProfileHandler builds a profile handler. Used by cmd/server/main.go
// to mount /profile on both portal and console route groups.
func NewProfileHandler(user UserQuerier, bus *event.Bus) *ProfileHandler {
	return &ProfileHandler{userQuerier: user, bus: bus}
}

// publish emits a profile change event. Actor / IP are denormalized downstream
// from the request-scoped auditctx.
func (h *ProfileHandler) publish(c *gin.Context, fields []string) {
	if h.bus == nil {
		return
	}
	userID, _ := authn.GetUserID(c)
	h.bus.Publish(c.Request.Context(), event.Event{
		Type:    event.ProfileUpdated,
		Payload: map[string]any{"user_id": userID, "fields": fields},
	})
}

// RegisterProfileRoutes mounts /profile + /profile/avatar onto rg. Public
// so main.go can mount on both portal and console groups.
func RegisterProfileRoutes(rg *gin.RouterGroup, h *ProfileHandler) {
	profile := rg.Group("/profile")
	{
		profile.GET("", h.getProfile)
		profile.PUT("", h.updateProfile)
		profile.PUT("/avatar", h.updateAvatar)
	}
}

// registerProfileRoutes is the legacy unexported entrypoint used by
// portal.Register. Kept for source-level compatibility while we transition
// to mounting from main.go.
func registerProfileRoutes(rg *gin.RouterGroup, h *ProfileHandler) {
	RegisterProfileRoutes(rg, h)
}

// getProfile returns the authenticated user's profile.
func (h *ProfileHandler) getProfile(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	user, err := h.userQuerier.GetByID(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to get profile", err)
		return
	}

	detail, err := h.userQuerier.GetDetail(c.Request.Context(), userID)
	if err != nil {
		// detail is optional, not fatal
		detail = &UserDetail{}
	}

	response.OK(c, gin.H{
		"user":   user,
		"detail": detail,
	})
}

// updateProfile updates the authenticated user's basic profile.
func (h *ProfileHandler) updateProfile(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	if err := h.userQuerier.UpdateProfile(c.Request.Context(), userID, req.DisplayName, req.Phone, req.Email); err != nil {
		response.MapError(c, err)
		return
	}

	h.publish(c, []string{"display_name", "phone", "email"})
	response.OK(c, nil)
}

// updateAvatar updates the authenticated user's avatar.
func (h *ProfileHandler) updateAvatar(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	var req UpdateAvatarRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	if err := h.userQuerier.UpdateAvatar(c.Request.Context(), userID, req.Avatar); err != nil {
		response.InternalError(c, "failed to update avatar", err)
		return
	}

	h.publish(c, []string{"avatar"})
	response.OK(c, nil)
}
