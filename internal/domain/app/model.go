package app

import (
	"encoding/json"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
	"gorm.io/gorm"
)

// Protocol constants.
const (
	ProtocolOIDC = "oidc"
	ProtocolSAML = "saml"
	ProtocolCAS  = "cas"
	// ProtocolForm is a form-fill (SWA) app: MXID stores a downstream credential
	// and a browser extension auto-submits the target site's login form. It mints
	// no signing key and no client_secret; the credential logic is an EE feature
	// (form_fill), so creating a form app requires that license.
	ProtocolForm = "form"
)

// Access policy constants.
const (
	AccessPolicyAll        = 1
	AccessPolicyAuthorized = 2
)

// Scope constants — controls cross-tenant visibility of an app.
//
//	ScopeTenant: app belongs to exactly one tenant; only that tenant's users
//	             see it. Default. 95% of deployments stay here.
//	ScopeShared: super_admin-only. app.tenant_id is NULL; the app appears in
//	             every tenant's catalogue and each tenant configures its own
//	             access policy. Used for cross-tenant SaaS apps.
const (
	ScopeTenant = 1
	ScopeShared = 2
)

// SubjectStrategy decides what user identifier MXID writes into the protocol
// token / NameID / CAS principal. Critical for shared apps where the same
// username can exist across tenants.
//
// Apps with ScopeShared MUST NOT use SubjectStrategyUsername — the create
// flow validates this and rejects the combination at the API boundary.
const (
	SubjectStrategyUsername         = "username"          // raw user.username (only safe for ScopeTenant)
	SubjectStrategyUsernameSuffixed = "username_suffixed" // username@tenant_code — safe everywhere
	SubjectStrategyEmail            = "email"             // user.email — already globally unique by domain
	SubjectStrategyPersistentID     = "persistent_id"     // snowflake string — opaque + globally unique
	SubjectStrategyPairwise         = "pairwise"          // OIDC pairwise sub (hash(client,user))
)

// App status constants.
const (
	StatusEnabled  = 1
	StatusDisabled = 2
)

// Client type constants (OIDC classification).
const (
	ClientTypeWebApp = "web_app"
	ClientTypeSPA    = "spa"
	ClientTypeNative = "native"
	ClientTypeM2M    = "m2m"
)

// Cert type constants.
const (
	CertTypeSigning    = "signing"
	CertTypeEncryption = "encryption"
)

// Cert status constants.
const (
	CertStatusActive   = 1
	CertStatusRotating = 2
	CertStatusRetired  = 3
)

// App represents the mxid_app table.
//
// ClientSecret stores the bcrypt hash of the OIDC client_secret. Plaintext is
// returned exactly once on create or rotate; subsequent reads expose hash only.
type App struct {
	ID             int64           `gorm:"column:id;primaryKey" json:"id"`
	TenantID       *int64          `gorm:"column:tenant_id" json:"tenant_id"` // NULL for ScopeShared
	Scope          int             `gorm:"column:scope;not null;default:1" json:"scope"`
	SubjectStrategy string         `gorm:"column:subject_strategy;not null;size:32;default:username" json:"subject_strategy"`
	Name           string          `gorm:"column:name;not null;size:128" json:"name"`
	Code           string          `gorm:"column:code;not null;size:64" json:"code"`
	Protocol       string          `gorm:"column:protocol;not null;size:16" json:"protocol"`
	Status         int             `gorm:"column:status;not null;default:1" json:"status"`
	Icon           *string         `gorm:"column:icon;size:512" json:"icon"`
	Env            *string         `gorm:"column:env;size:64" json:"env"` // environment label: qa/uat/prod/... or custom; NULL = unlabelled
	Description    *string         `gorm:"column:description;type:text" json:"description"`
	ClientID       *string         `gorm:"column:client_id;size:128" json:"client_id"`
	ClientSecret   *string         `gorm:"column:client_secret;size:255" json:"-"`
	ClientType     string          `gorm:"column:client_type;not null;size:20;default:web_app" json:"client_type"`
	HomeURL        *string         `gorm:"column:home_url;size:512" json:"home_url"`
	IsFirstParty   bool            `gorm:"column:is_first_party;not null;default:true" json:"is_first_party"`
	RequireConsent bool            `gorm:"column:require_consent;not null;default:false" json:"require_consent"`
	ProtocolConfig json.RawMessage `gorm:"column:protocol_config;type:jsonb;not null;default:'{}'" json:"protocol_config"`
	LoginURL       *string         `gorm:"column:login_url;size:512" json:"login_url"`
	RedirectURIs   json.RawMessage `gorm:"column:redirect_uris;type:jsonb;default:'[]'" json:"redirect_uris"`
	LogoutURL      *string         `gorm:"column:logout_url;size:512" json:"logout_url"`
	AccessPolicy   int             `gorm:"column:access_policy;not null;default:1" json:"access_policy"`
	CreatedAt      time.Time       `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt      time.Time       `gorm:"column:updated_at;not null" json:"updated_at"`
	CreatedBy      *int64          `gorm:"column:created_by" json:"created_by"`
	UpdatedBy      *int64          `gorm:"column:updated_by" json:"updated_by"`
	DeletedAt      gorm.DeletedAt  `gorm:"column:deleted_at;index" json:"-"`
}

// TableName returns the table name for App.
func (App) TableName() string {
	return "mxid_app"
}

// AuditResource implements audit.Audited.
func (App) AuditResource() string {
	return "app"
}

// TenantScoped marks mxid_app for automatic tenant isolation.
func (App) TenantScoped() {}

// TenantScopePredicate keeps globally-shared apps (tenant_id IS NULL,
// Scope=ScopeShared) visible in every tenant's catalogue. A naive
// `tenant_id = ?` would hide them — mirrors repository_impl.go's List filter.
func (App) TenantScopePredicate() (string, bool) {
	return "tenant_id = ? OR tenant_id IS NULL", true
}

// AppGroup represents the mxid_app_group table. ParentID nil = top-level
// (root) group; cycle prevention is the service layer's responsibility.
type AppGroup struct {
	ID        int64          `gorm:"column:id;primaryKey" json:"id"`
	TenantID  int64          `gorm:"column:tenant_id;not null" json:"tenant_id"`
	Name      string         `gorm:"column:name;not null;size:128" json:"name"`
	Code      string         `gorm:"column:code;not null;size:64" json:"code"`
	ParentID  *int64         `gorm:"column:parent_id" json:"parent_id"`
	SortOrder int            `gorm:"column:sort_order;not null;default:0" json:"sort_order"`
	CreatedAt time.Time      `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt time.Time      `gorm:"column:updated_at;not null" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

// TableName returns the table name for AppGroup.
func (AppGroup) TableName() string {
	return "mxid_app_group"
}

// TenantScoped marks mxid_app_group for automatic tenant isolation.
func (AppGroup) TenantScoped() {}

// AppGroupRel represents the mxid_app_group_rel table.
type AppGroupRel struct {
	ID        int64     `gorm:"column:id;primaryKey" json:"id"`
	AppID     int64     `gorm:"column:app_id;not null" json:"app_id"`
	GroupID   int64     `gorm:"column:group_id;not null" json:"group_id"`
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName returns the table name for AppGroupRel.
func (AppGroupRel) TableName() string {
	return "mxid_app_group_rel"
}

// AppAccess represents the mxid_app_access table.
type AppAccess struct {
	ID          int64     `gorm:"column:id;primaryKey" json:"id"`
	AppID       int64     `gorm:"column:app_id;not null" json:"app_id"`
	SubjectType string    `gorm:"column:subject_type;not null;size:16" json:"subject_type"`
	SubjectID   int64     `gorm:"column:subject_id;not null" json:"subject_id"`
	CreatedAt   time.Time `gorm:"column:created_at;not null" json:"created_at"`
	CreatedBy   *int64    `gorm:"column:created_by" json:"created_by"`
}

// TableName returns the table name for AppAccess.
func (AppAccess) TableName() string {
	return "mxid_app_access"
}

// AppAccount represents the mxid_app_account table.
type AppAccount struct {
	ID         int64     `gorm:"column:id;primaryKey" json:"id"`
	AppID      int64     `gorm:"column:app_id;not null" json:"app_id"`
	UserID     int64     `gorm:"column:user_id;not null" json:"user_id"`
	Account    string    `gorm:"column:account;not null;size:256" json:"account"`
	// Credential is AES-256-GCM encrypted at rest via crypto.Secret's
	// driver.Valuer/Scanner and serializes to a masked sentinel (never the
	// plaintext) in JSON responses. Requires crypto.SetSecretMasterKey at boot.
	Credential crypto.Secret `gorm:"column:credential;size:512" json:"credential"`
	CreatedAt  time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt  time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

// TableName returns the table name for AppAccount.
func (AppAccount) TableName() string {
	return "mxid_app_account"
}

// AppCert represents the mxid_app_cert table.
//
// PrivateKey stores either plaintext PEM (legacy) or AES-256-GCM ciphertext
// (when Encrypted=true). Ciphertext layout: base64(nonce || ciphertext || tag).
// Decryption requires the master key from MXID_KEY_ENCRYPTION_KEY env var.
type AppCert struct {
	ID         int64      `gorm:"column:id;primaryKey" json:"id"`
	AppID      int64      `gorm:"column:app_id;not null" json:"app_id"`
	CertType   string     `gorm:"column:cert_type;not null;size:16" json:"cert_type"`
	Algorithm  string     `gorm:"column:algorithm;not null;size:16" json:"algorithm"`
	PublicKey  string     `gorm:"column:public_key;type:text;not null" json:"public_key"`
	PrivateKey string     `gorm:"column:private_key;type:text;not null" json:"-"`
	KID        *string    `gorm:"column:kid;size:64" json:"kid"`
	NotBefore  time.Time  `gorm:"column:not_before;not null" json:"not_before"`
	ExpiresAt  *time.Time `gorm:"column:expires_at" json:"expires_at"`
	Encrypted  bool       `gorm:"column:encrypted;not null;default:false" json:"encrypted"`
	Status     int        `gorm:"column:status;not null;default:1" json:"status"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName returns the table name for AppCert.
func (AppCert) TableName() string {
	return "mxid_app_cert"
}
