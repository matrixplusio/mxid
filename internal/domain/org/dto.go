package org

import "time"

// CreateOrgRequest is the request body for creating an organization.
//
// ParentID uses ,string,omitempty so the frontend can send the snowflake
// parent ID as a JSON string (avoids JS Number precision loss); omit or
// null for a root-level org.
type CreateOrgRequest struct {
	Name      string `json:"name" binding:"required,max=128"`
	Code      string `json:"code" binding:"required,max=64"`
	ParentID  *int64 `json:"parent_id,string,omitempty"`
	SortOrder int    `json:"sort_order"`
}

// UpdateOrgRequest is the request body for updating an organization.
type UpdateOrgRequest struct {
	Name      string `json:"name" binding:"required,max=128"`
	SortOrder int    `json:"sort_order"`
	Status    int16  `json:"status" binding:"oneof=0 1"`
}

// MoveOrgRequest is the request body for moving an organization.
// ParentID is nil for moving to the root (no parent).
type MoveOrgRequest struct {
	ParentID *int64 `json:"parent_id,string,omitempty"`
}

// AddMemberRequest is the request body for adding a member to an organization.
type AddMemberRequest struct {
	UserID    int64 `json:"user_id,string" binding:"required"`
	IsPrimary bool  `json:"is_primary"`
}

// OrgResponse is the API response for a single organization.
type OrgResponse struct {
	ID        int64          `json:"id,string"`
	TenantID  int64          `json:"tenant_id,string"`
	Name      string         `json:"name"`
	Code      string         `json:"code"`
	ParentID  *int64         `json:"parent_id,string,omitempty"`
	Path      string         `json:"path"`
	SortOrder int            `json:"sort_order"`
	Status    int16          `json:"status"`
	Extra     JSONMap        `json:"extra"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	Children  []*OrgResponse `json:"children,omitempty"`
}

// OrgTreeResponse is the recursive tree structure for organizations.
type OrgTreeResponse struct {
	Items []*OrgResponse `json:"items"`
}

// UserOrgInfo is one org-membership row enriched for display on the user
// detail page: which org the user is planted in, plus whether it's primary.
type UserOrgInfo struct {
	OrgID     int64  `json:"org_id,string"`
	Name      string `json:"name"`
	Code      string `json:"code"`
	Path      string `json:"path"`
	IsPrimary bool   `json:"is_primary"`
}

// ToOrgResponse converts an Organization model to an OrgResponse.
func ToOrgResponse(org *Organization) *OrgResponse {
	return &OrgResponse{
		ID:        org.ID,
		TenantID:  org.TenantID,
		Name:      org.Name,
		Code:      org.Code,
		ParentID:  org.ParentID,
		Path:      org.Path,
		SortOrder: org.SortOrder,
		Status:    org.Status,
		Extra:     org.Extra,
		CreatedAt: org.CreatedAt,
		UpdatedAt: org.UpdatedAt,
	}
}
