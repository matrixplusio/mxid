package user

import (
	"time"

	"github.com/imkerbos/mxid/pkg/mask"
)

// CreateUserRequest is the request body for creating a user.
type CreateUserRequest struct {
	Username    string  `json:"username" binding:"required,min=2,max=128"`
	Email       *string `json:"email" binding:"omitempty,email,max=256"`
	Phone       *string `json:"phone" binding:"omitempty,max=32"`
	DisplayName *string `json:"display_name" binding:"omitempty,max=128"`
	Password    string  `json:"password" binding:"required,min=6,max=128"`
	Status      *int    `json:"status" binding:"omitempty,oneof=1 2 3 4"`
}

// UpdateUserRequest is the request body for updating a user.
type UpdateUserRequest struct {
	Email       *string `json:"email" binding:"omitempty,email,max=256"`
	Phone       *string `json:"phone" binding:"omitempty,max=32"`
	DisplayName *string `json:"display_name" binding:"omitempty,max=128"`
	// Avatar holds either a URL or an inline base64 data URL. Cap ~5 MB of chars:
	// the client crops to a small square PNG (well under this), and even a raw
	// 3 MB image → ~4 M base64 chars fits — bounded to reject abusive payloads.
	Avatar      *string `json:"avatar" binding:"omitempty,max=5242880"`
	Status      *int    `json:"status" binding:"omitempty,oneof=1 2 3 4"`
}

// UpdateStatusRequest is the request body for updating user status.
type UpdateStatusRequest struct {
	Status int `json:"status" binding:"required,oneof=1 2 3 4"`
}

// LockUserRequest is the request body for admin-initiated account lock.
// Reason is recorded in the lock event payload for audit trails.
type LockUserRequest struct {
	Reason string `json:"reason" binding:"required,max=256"`
}

// BatchAction enumerates the allowed bulk operations on a set of users.
// Group add/remove are NOT here — those go through the group module's
// batch member endpoints to keep group-membership logic in one place.
type BatchAction string

const (
	BatchActionEnable  BatchAction = "enable"
	BatchActionDisable BatchAction = "disable"
	BatchActionDelete  BatchAction = "delete"
)

// BatchUsersRequest carries a list of user IDs plus the action to apply.
// IDs cap at 500 per call so the wrapping transaction stays bounded.
//
// IDs is []string so the frontend can send snowflake int64 values without
// losing precision (encoding/json `,string` does not propagate into slice
// elements). The handler parses them into int64 before invoking the service.
type BatchUsersRequest struct {
	IDs    []string    `json:"ids" binding:"required,min=1,max=500"`
	Action BatchAction `json:"action" binding:"required,oneof=enable disable delete"`
}

// BatchItemError reports a single user that failed in a batch operation.
// The batch endpoint does NOT short-circuit on the first error — partial
// success is the norm (some IDs may not exist or be unauthorised).
type BatchItemError struct {
	ID    int64  `json:"id,string"`
	Error string `json:"error"`
}

// BatchUsersResponse is the result payload for /users:batch.
type BatchUsersResponse struct {
	Affected int              `json:"affected"`
	Errors   []BatchItemError `json:"errors"`
}

// ChangePasswordRequest is the request body for a user changing their own password.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6,max=128"`
}

// ResetPasswordRequest is the request body for an admin resetting a user's password.
//
// MustChange (default true) forces the user to pick a new password on their
// next login. Set false only for headless / system accounts where there's no
// interactive flow to satisfy the prompt.
type ResetPasswordRequest struct {
	NewPassword string `json:"new_password" binding:"required,min=6,max=128"`
	MustChange  *bool  `json:"must_change,omitempty"`
}

// UpdateDetailRequest is the request body for editing a user's extended profile.
// All fields are optional — only those present in the JSON are touched (nil
// means "do not change", explicit "" means "clear the field"). Birthday is a
// free-form ISO-8601 date string; the storage layer keeps it as text.
type UpdateDetailRequest struct {
	Gender     *int    `json:"gender" binding:"omitempty,oneof=0 1 2"`
	Birthday   *string `json:"birthday" binding:"omitempty,max=32"`
	Address    *string `json:"address" binding:"omitempty,max=512"`
	EmployeeNo *string `json:"employee_no" binding:"omitempty,max=64"`
	JobTitle   *string `json:"job_title" binding:"omitempty,max=128"`
	Department *string `json:"department" binding:"omitempty,max=256"`
}

// UserMFAResponse is the API view of an enrolled MFA factor. The secret is
// never serialised — only the metadata an admin needs to decide whether to
// force-unenroll.
type UserMFAResponse struct {
	Type      string `json:"type"`
	IsDefault bool   `json:"is_default"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// UserIdentityResponse is the API view of a third-party identity binding.
type UserIdentityResponse struct {
	ID           int64  `json:"id,string"`
	ProviderType string `json:"provider_type"`
	ProviderID   string `json:"provider_id"`
	ExternalID   string `json:"external_id"`
	ExternalName string `json:"external_name,omitempty"`
	CreatedAt    string `json:"created_at"`
}

// ListUsersRequest holds query parameters for listing users.
type ListUsersRequest struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Search   string `form:"search"`
	Status   *int   `form:"status"`
	OrgID    *int64 `form:"org_id"`
}

// UserResponse is the API response for a user.
//
// ID + TenantID use ,string because snowflake int64 IDs exceed JS Number's
// safe integer range; returning them as numbers makes the frontend round
// the trailing digits and every detail-page lookup 404s.
type UserResponse struct {
	ID                int64              `json:"id,string"`
	TenantID          int64              `json:"tenant_id,string"`
	Username          string             `json:"username"`
	Email             *string            `json:"email"`
	Phone             *string            `json:"phone"`
	DisplayName       *string            `json:"display_name"`
	Avatar            *string            `json:"avatar"`
	Status            int                `json:"status"`
	// MFAEnabled is true when the user has ≥1 verified MFA method. Populated only
	// on the list view (batched); zero-valued on single-user responses.
	MFAEnabled        bool               `json:"mfa_enabled"`
	LastLoginAt       *time.Time         `json:"last_login_at"`
	LastLoginIP       *string            `json:"last_login_ip"`
	PasswordChangedAt *time.Time         `json:"password_changed_at"`
	MustChangePwd     bool               `json:"must_change_pwd"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
	CreatedBy         *int64             `json:"created_by,string,omitempty"`
	UpdatedBy         *int64             `json:"updated_by,string,omitempty"`
	Detail            *UserDetailResponse `json:"detail,omitempty"`
}

// UserDetailResponse is the API response for user detail.
type UserDetailResponse struct {
	Gender     *int    `json:"gender"`
	Birthday   *string `json:"birthday"`
	Address    *string `json:"address"`
	EmployeeNo *string `json:"employee_no"`
	JobTitle   *string `json:"job_title"`
	Department *string `json:"department"`
	Extra      *string `json:"extra"`
}

// ToResponseMasked converts a User model to a UserResponse with phone, email,
// and last-login IP redacted. Used for list endpoints and any view where the
// caller does not have a clear need-to-know for the raw PII. Detail block is
// dropped because it carries address / employee_no / birthday which are
// equally sensitive.
//
// Detail / self-profile / admin-edit views call ToResponse instead and MUST
// emit an audit event for the PII access.
func ToResponseMasked(u *User) *UserResponse {
	r := ToResponse(u, nil)
	if r.Email != nil {
		v := mask.Email(*r.Email)
		r.Email = &v
	}
	if r.Phone != nil {
		v := mask.Phone(*r.Phone)
		r.Phone = &v
	}
	if r.LastLoginIP != nil && *r.LastLoginIP != "" {
		v := maskIP(*r.LastLoginIP)
		r.LastLoginIP = &v
	}
	return r
}

// maskIP redacts the last octet of an IPv4 (192.168.1.42 → 192.168.1.*) and
// the last group of an IPv6 (::1 → ::*). Anything that doesn't look like an
// IP is passed through unchanged so we don't lose hostname diagnostics.
func maskIP(s string) string {
	if s == "" {
		return s
	}
	// IPv6 takes precedence: any colon means it's IPv6 shape.
	if idx := lastByte(s, ':'); idx >= 0 {
		return s[:idx+1] + "*"
	}
	if idx := lastByte(s, '.'); idx >= 0 {
		return s[:idx+1] + "*"
	}
	return s
}

func lastByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// ToResponse converts a User model to a UserResponse.
func ToResponse(u *User, detail *UserDetail) *UserResponse {
	resp := &UserResponse{
		ID:                u.ID,
		TenantID:          u.TenantID,
		Username:          u.Username,
		Email:             u.Email,
		Phone:             u.Phone,
		DisplayName:       u.DisplayName,
		Avatar:            u.Avatar,
		Status:            u.Status,
		LastLoginAt:       u.LastLoginAt,
		LastLoginIP:       u.LastLoginIP,
		PasswordChangedAt: u.PasswordChangedAt,
		MustChangePwd:     u.MustChangePwd,
		CreatedAt:         u.CreatedAt,
		UpdatedAt:         u.UpdatedAt,
		CreatedBy:         u.CreatedBy,
		UpdatedBy:         u.UpdatedBy,
	}

	if detail != nil {
		resp.Detail = &UserDetailResponse{
			Gender:     detail.Gender,
			Birthday:   detail.Birthday,
			Address:    detail.Address,
			EmployeeNo: detail.EmployeeNo,
			JobTitle:   detail.JobTitle,
			Department: detail.Department,
			Extra:      detail.Extra,
		}
	}

	return resp
}
