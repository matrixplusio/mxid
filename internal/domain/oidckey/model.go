// Package oidckey manages the provider-level OIDC signing keyset: a single
// logical keyset for the OIDC issuer, shared by all clients, with active/passive
// rotation. This is deliberately separate from the per-app SAML signing certs in
// internal/domain/app (mxid_app_cert) — see migration 000036 for the rationale.
package oidckey

import "time"

// Key lifecycle states. Mirror app.CertStatus* so operators see one model.
const (
	StatusActive   = 1 // signs new tokens; exactly one at a time
	StatusRotating = 2 // verify-only, still published in JWKS during overlap
	StatusRetired  = 3 // dropped from JWKS
)

// ProviderKey is one entry in the OIDC issuer keyset.
type ProviderKey struct {
	ID         int64      `gorm:"column:id;primaryKey"`
	KID        string     `gorm:"column:kid;not null;size:64"`
	Algorithm  string     `gorm:"column:algorithm;not null;size:16"`
	PublicKey  string     `gorm:"column:public_key;type:text;not null"`  // PKIX PEM, plaintext
	PrivateKey string     `gorm:"column:private_key;type:text;not null"` // PKCS#1 PEM, KEK-encrypted
	Status     int        `gorm:"column:status;not null;default:1"`
	NotBefore  time.Time  `gorm:"column:not_before;not null"`
	ExpiresAt  *time.Time `gorm:"column:expires_at"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null"`
}

// TableName returns the GORM table name.
func (ProviderKey) TableName() string {
	return "mxid_oidc_keyset"
}

// AuditResource implements audit.Audited.
func (ProviderKey) AuditResource() string {
	return "oidc_provider_key"
}
