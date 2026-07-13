package app

import (
	"encoding/json"
	"time"
)

// CreateAppRequest is the request body for creating an application.
//
// Scope + SubjectStrategy control multi-tenant behaviour:
//
//   - Scope=1 (tenant): app belongs to the caller's tenant. Default.
//   - Scope=2 (shared): super_admin only; app visible across all tenants.
//
// SubjectStrategy decides the user identifier emitted by the protocol layer
// (OIDC sub/preferred_username, SAML NameID, CAS principal). For shared
// apps "username" is rejected because it can collide across tenants.
type CreateAppRequest struct {
	Name            string         `json:"name" binding:"required,max=128"`
	Code            string         `json:"code" binding:"required,max=64"`
	Protocol        string         `json:"protocol" binding:"required,oneof=oidc saml cas form"`
	ClientType      string         `json:"client_type" binding:"omitempty,oneof=web_app spa native m2m"`
	Scope           *int           `json:"scope" binding:"omitempty,oneof=1 2"`
	SubjectStrategy *string        `json:"subject_strategy" binding:"omitempty,oneof=username username_suffixed email persistent_id pairwise"`
	Icon            *string        `json:"icon" binding:"omitempty,max=512"`
	Env             *string        `json:"env" binding:"omitempty,max=64"`
	Description     *string        `json:"description"`
	HomeURL         *string        `json:"home_url" binding:"omitempty,max=512"`
	LoginURL        *string        `json:"login_url" binding:"omitempty,max=512"`
	RedirectURIs    []string       `json:"redirect_uris"`
	LogoutURL       *string        `json:"logout_url" binding:"omitempty,max=512"`
	AccessPolicy    *int           `json:"access_policy" binding:"omitempty,oneof=1 2"`
	IsFirstParty    *bool          `json:"is_first_party"`
	RequireConsent  *bool          `json:"require_consent"`
	ProtocolConfig  map[string]any `json:"protocol_config"`
}

// UpdateAppRequest is the request body for updating an application.
//
// SubjectStrategy can be changed post-create. Scope cannot — converting a
// tenant app into a shared one (or vice versa) would invalidate every
// existing user binding, so it's deliberately not patchable.
type UpdateAppRequest struct {
	Name            *string        `json:"name" binding:"omitempty,max=128"`
	SubjectStrategy *string        `json:"subject_strategy" binding:"omitempty,oneof=username username_suffixed email persistent_id pairwise"`
	Icon            *string        `json:"icon" binding:"omitempty,max=512"`
	Env             *string        `json:"env" binding:"omitempty,max=64"`
	Description     *string        `json:"description"`
	HomeURL         *string        `json:"home_url" binding:"omitempty,max=512"`
	LoginURL        *string        `json:"login_url" binding:"omitempty,max=512"`
	RedirectURIs    []string       `json:"redirect_uris"`
	LogoutURL       *string        `json:"logout_url" binding:"omitempty,max=512"`
	AccessPolicy    *int           `json:"access_policy" binding:"omitempty,oneof=1 2"`
	IsFirstParty    *bool          `json:"is_first_party"`
	RequireConsent  *bool          `json:"require_consent"`
	ProtocolConfig  map[string]any `json:"protocol_config"`
}

// CreateAppResult carries the freshly created app plus the one-time client_secret plaintext.
type CreateAppResult struct {
	App                *App
	ClientSecretPlain  string // empty for spa / native
	SigningKID         string // kid of the generated signing key (OIDC only)
}

// RotateSecretResult carries the new client_secret plaintext (one-time exposure).
type RotateSecretResult struct {
	ClientSecretPlain string
}

// UpdateStatusRequest is the request body for updating app status.
type UpdateStatusRequest struct {
	Status int `json:"status" binding:"required,oneof=1 2"`
}

// UpdateProtocolConfigRequest is the request body for updating protocol config.
type UpdateProtocolConfigRequest struct {
	ProtocolConfig map[string]any `json:"protocol_config" binding:"required"`
}

// AddAccessRequest is the request body for adding an access authorization.
type AddAccessRequest struct {
	SubjectType string `json:"subject_type" binding:"required,max=16"`
	SubjectID   int64  `json:"subject_id,string" binding:"required"`
}

// AppGroupRequest is the request body for creating an app group.
type AppGroupRequest struct {
	Name      string `json:"name" binding:"required,max=128"`
	Code      string `json:"code" binding:"required,max=64"`
	ParentID  *int64 `json:"parent_id,string,omitempty"`
	SortOrder *int   `json:"sort_order"`
}

// UpdateAppGroupRequest is the request body for updating an app group.
// ParentID accepts:
//   - omit / null       → leave parent unchanged
//   - explicit 0        → move to root (use 0 instead of null so the JSON
//                          tri-state stays simple; service translates 0→nil)
//   - any other int64   → reparent under that group
type UpdateAppGroupRequest struct {
	Name      *string `json:"name" binding:"omitempty,max=128"`
	ParentID  *int64  `json:"parent_id,string,omitempty"`
	SortOrder *int    `json:"sort_order"`
}

// AddAppToGroupRequest is the request body for adding an app to a group.
type AddAppToGroupRequest struct {
	AppID int64 `json:"app_id,string" binding:"required"`
}

// AppAccountRequest is the request body for creating/updating an app account.
type AppAccountRequest struct {
	UserID     int64   `json:"user_id,string" binding:"required"`
	Account    string  `json:"account" binding:"required,max=256"`
	Credential *string `json:"credential" binding:"omitempty,max=512"`
}

// AppResponse is the API response for an application.
//
// ClientSecret is never echoed back after create / rotate. Field is reserved
// for the one-time plaintext returned only via CreateAppResult / RotateSecretResult.
type AppResponse struct {
	ID              int64          `json:"id,string"`
	TenantID        *int64         `json:"tenant_id,string,omitempty"` // null = shared app
	Scope           int            `json:"scope"`                       // 1=tenant 2=shared
	SubjectStrategy string         `json:"subject_strategy"`
	Name            string         `json:"name"`
	Code            string         `json:"code"`
	Protocol        string         `json:"protocol"`
	ClientType      string         `json:"client_type"`
	Status          int            `json:"status"`
	Icon           *string        `json:"icon"`
	Env            *string        `json:"env"`
	Description    *string        `json:"description"`
	ClientID       *string        `json:"client_id"`
	ClientSecret   string         `json:"client_secret,omitempty"` // populated only by create / rotate
	HomeURL        *string        `json:"home_url"`
	IsFirstParty   bool           `json:"is_first_party"`
	RequireConsent bool           `json:"require_consent"`
	ProtocolConfig map[string]any `json:"protocol_config"`
	LoginURL       *string        `json:"login_url"`
	RedirectURIs   []string       `json:"redirect_uris"`
	LogoutURL      *string        `json:"logout_url"`
	AccessPolicy   int            `json:"access_policy"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	CreatedBy      *int64         `json:"created_by,string,omitempty"`
	UpdatedBy      *int64         `json:"updated_by,string,omitempty"`
}

// AppGroupResponse is the API response for an app group.
type AppGroupResponse struct {
	ID        int64     `json:"id,string"`
	TenantID  int64     `json:"tenant_id,string"`
	Name      string    `json:"name"`
	Code      string    `json:"code"`
	ParentID  *int64    `json:"parent_id,string,omitempty"`
	SortOrder int       `json:"sort_order"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AppAccessResponse is the API response for an access authorization.
type AppAccessResponse struct {
	ID          int64     `json:"id,string"`
	AppID       int64     `json:"app_id,string"`
	SubjectType string    `json:"subject_type"`
	SubjectID   int64     `json:"subject_id,string"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   *int64    `json:"created_by,string,omitempty"`
}

// AppCertResponse is the API response for an app certificate.
type AppCertResponse struct {
	ID        int64      `json:"id,string"`
	AppID     int64      `json:"app_id,string"`
	CertType  string     `json:"cert_type"`
	Algorithm string     `json:"algorithm"`
	PublicKey string     `json:"public_key"`
	ExpiresAt *time.Time `json:"expires_at"`
	Status    int        `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
}

// ToAppResponse converts an App model to an AppResponse.
//
// The bcrypt-hashed client_secret stored on the model is intentionally
// never emitted; the one-time plaintext is carried in CreateAppResult /
// RotateSecretResult instead.
func ToAppResponse(a *App) *AppResponse {
	resp := &AppResponse{
		ID:              a.ID,
		TenantID:        a.TenantID,
		Scope:           a.Scope,
		SubjectStrategy: a.SubjectStrategy,
		Name:            a.Name,
		Code:            a.Code,
		Protocol:       a.Protocol,
		ClientType:     a.ClientType,
		Status:         a.Status,
		Icon:           a.Icon,
		Env:            a.Env,
		Description:    a.Description,
		ClientID:       a.ClientID,
		HomeURL:        a.HomeURL,
		IsFirstParty:   a.IsFirstParty,
		RequireConsent: a.RequireConsent,
		LoginURL:       a.LoginURL,
		LogoutURL:      a.LogoutURL,
		AccessPolicy:   a.AccessPolicy,
		CreatedAt:      a.CreatedAt,
		UpdatedAt:      a.UpdatedAt,
		CreatedBy:      a.CreatedBy,
		UpdatedBy:      a.UpdatedBy,
	}

	// Unmarshal protocol_config from JSON
	if len(a.ProtocolConfig) > 0 {
		var pc map[string]any
		if err := json.Unmarshal(a.ProtocolConfig, &pc); err == nil {
			resp.ProtocolConfig = pc
		}
	}
	if resp.ProtocolConfig == nil {
		resp.ProtocolConfig = make(map[string]any)
	}

	// Unmarshal redirect_uris from JSON
	if len(a.RedirectURIs) > 0 {
		var uris []string
		if err := json.Unmarshal(a.RedirectURIs, &uris); err == nil {
			resp.RedirectURIs = uris
		}
	}
	if resp.RedirectURIs == nil {
		resp.RedirectURIs = []string{}
	}

	return resp
}

// ToAppGroupResponse converts an AppGroup model to an AppGroupResponse.
func ToAppGroupResponse(g *AppGroup) *AppGroupResponse {
	return &AppGroupResponse{
		ID:        g.ID,
		TenantID:  g.TenantID,
		Name:      g.Name,
		Code:      g.Code,
		ParentID:  g.ParentID,
		SortOrder: g.SortOrder,
		CreatedAt: g.CreatedAt,
		UpdatedAt: g.UpdatedAt,
	}
}

// ToAppAccessResponse converts an AppAccess model to an AppAccessResponse.
func ToAppAccessResponse(a *AppAccess) *AppAccessResponse {
	return &AppAccessResponse{
		ID:          a.ID,
		AppID:       a.AppID,
		SubjectType: a.SubjectType,
		SubjectID:   a.SubjectID,
		CreatedAt:   a.CreatedAt,
		CreatedBy:   a.CreatedBy,
	}
}

// ToAppCertResponse converts an AppCert model to an AppCertResponse.
func ToAppCertResponse(c *AppCert) *AppCertResponse {
	return &AppCertResponse{
		ID:        c.ID,
		AppID:     c.AppID,
		CertType:  c.CertType,
		Algorithm: c.Algorithm,
		PublicKey: c.PublicKey,
		ExpiresAt: c.ExpiresAt,
		Status:    c.Status,
		CreatedAt: c.CreatedAt,
	}
}
