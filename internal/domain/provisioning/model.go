// Package provisioning holds the per-app outbound-provisioning config (Phase
// 1.2, L2): the SCIM/admin credentials a customer's IT granted so offboarding
// can deactivate the downstream account, not just cut SSO.
//
// The schema + config CRUD live in CE (foundational, grandfathered). The actual
// SCIM connector that consumes this config lives ONLY in the EE binary
// (license-gated `scim`); CE just stores the config and gates the offboarding
// enqueue on whether the EE connector is built in.
package provisioning

import "time"

// Connector types.
const (
	ConnectorSCIM2 = "scim2"
)

// Config is one app's provisioning credentials. Disabled by default so MXID
// never touches a customer's directory until an admin explicitly opts in.
type Config struct {
	AppID     int64     `gorm:"column:app_id;primaryKey"`
	TenantID  int64     `gorm:"column:tenant_id"`
	Enabled   bool      `gorm:"column:enabled"`
	Connector string    `gorm:"column:connector"`
	BaseURL   string    `gorm:"column:base_url"`
	TokenEnc  string    `gorm:"column:token_enc"` // AES-encrypted bearer token
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName maps Config to its table.
func (Config) TableName() string { return "mxid_app_provisioning" }

// TenantScoped marks Config for the fail-closed tenantscope GORM plugin, so
// every read/write is auto-filtered by the caller's tenant. Without it the
// repo keyed on app_id alone, letting a tenant admin read or hijack another
// tenant's per-app SCIM provisioning config (base_url/token) by app id.
func (Config) TenantScoped() {}
