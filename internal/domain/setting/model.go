// Package setting holds runtime-tunable configurations.
//
// Anything an operator might want to change without redeploying lives here:
// SMTP, password policy, branding, default protocol parameters, etc.
// config.yaml stays minimal (bootstrap-only: DSN, KEK, log level, ports).
//
// Two layers:
//
//	Repository    raw KV against mxid_setting (JSON value, no decryption)
//	Service       typed Get/Set helpers per category, transparent AES on
//	              sensitive fields (SMTP password, SMS secret, etc).
//
// Each typed setting category is a struct in this file. To add a new
// category, append a struct + define `Key*` constant + add a `Default*`
// helper. Service.GetTyped[T] handles the rest.
package setting

import (
	"encoding/json"
	"time"
)

// Setting is the raw KV row from mxid_setting.
type Setting struct {
	Key       string    `gorm:"column:key;primaryKey;size:128" json:"key"`
	TenantID  int64     `gorm:"column:tenant_id;primaryKey;default:0" json:"tenant_id"`
	Value     []byte    `gorm:"column:value;type:jsonb;not null" json:"-"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updated_at"`
	UpdatedBy *int64    `gorm:"column:updated_by" json:"updated_by"`
}

func (Setting) TableName() string { return "mxid_setting" }

// AuditResource implements audit.Audited.
func (Setting) AuditResource() string { return "setting" }

// TenantScoped marks mxid_setting for automatic tenant isolation.
func (Setting) TenantScoped() {}

// TenantScopePredicate keeps the tenant_id=0 GLOBAL-default rows visible so the
// settings fallback (tenant override -> global default) keeps working. A naive
// `tenant_id = ?` would hide the global defaults.
func (Setting) TenantScopePredicate() (string, bool) {
	return "tenant_id IN (?, 0)", true
}

// Decode unmarshals the JSON value into the given target.
func (s *Setting) Decode(target any) error {
	return json.Unmarshal(s.Value, target)
}

/* ───────────────────── Keys ───────────────────── */

// Well-known keys. Prefixed by category so list filtering stays simple.
const (
	KeyMailSMTP           = "mail.smtp"
	KeyMailTemplates      = "mail.templates"
	KeySMS                = "sms"
	KeySecurityPolicy     = "security.policy"
	KeyBranding           = "branding"
	KeyLoginMethods       = "login.methods"
	KeyProtocolDefault    = "protocol.defaults"
	KeyAuditPolicy        = "audit.policy"
	KeyLocalization       = "localization"
	KeyLicense            = "license"
	KeyExternalURLs       = "external.urls"
	KeyMFAPolicy          = "security.mfa"
	KeyConditionalAccess  = "security.conditional_access"
	KeyOffboardingWebhook = "offboarding.webhook"
)

// MFA enforcement modes for MFAPolicy.Mode.
const (
	MFAModeOff       = "off"        // MFA not enforced; step-up is audit-only
	MFAModeAdminOnly = "admin_only" // console-eligible admins must use MFA
	MFAModeAll       = "all"        // every user must use MFA
)

/* ──────────────── Category structs ──────────────── */

// MailSMTP — outbound mail server config. Password is stored AES-encrypted
// at the JSON layer (see service.go); callers receive plaintext.
type MailSMTP struct {
	Enabled      bool   `json:"enabled"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	Password     string `json:"password"`     // AES-encrypted at rest
	FromAddress  string `json:"from_address"` // e.g. "MXID <noreply@example.com>"
	FromName     string `json:"from_name"`
	TLSMode      string `json:"tls_mode"` // "none" | "starttls" | "tls"
	SkipVerify   bool   `json:"skip_verify"`
	HeloHostname string `json:"helo_hostname,omitempty"`
}

// MailTemplates — subject/body templates per kind. Body is a Go text/template
// string; available vars depend on the template (e.g. .Link / .Code / .User).
type MailTemplates struct {
	EmailVerify   MailTemplate `json:"email_verify"`
	PasswordReset MailTemplate `json:"password_reset"`
	Welcome       MailTemplate `json:"welcome"`
	MagicLink     MailTemplate `json:"magic_link"`
}

type MailTemplate struct {
	Subject string `json:"subject"`
	Body    string `json:"body"` // HTML allowed
}

// SecurityPolicy — password rules + lockout. Mirrors config.yaml's old
// security.* tree; migrating it here lets admins change without restart.
type SecurityPolicy struct {
	Password PasswordPolicy `json:"password"`
	Login    LoginPolicy    `json:"login"`
	Session  SessionPolicy  `json:"session"`
}

type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumber    bool `json:"require_number"`
	RequireSpecial   bool `json:"require_special"`
	HistoryCount     int  `json:"history_count"`
	ExpireDays       int  `json:"expire_days"`
	ExpireWarnDays   int  `json:"expire_warn_days"`
}

type LoginPolicy struct {
	MaxFailedAttempts    int `json:"max_failed_attempts"`
	LockoutMinutes       int `json:"lockout_minutes"`
	CaptchaAfterFailures int `json:"captcha_after_failures"`
}

type SessionPolicy struct {
	IdleMinutes     int `json:"idle_minutes"`
	AbsoluteHours   int `json:"absolute_hours"`
	RememberMeHours int `json:"remember_me_hours"`
}

// Branding — UI customization shown on portal login page.
type Branding struct {
	LogoURL         string `json:"logo_url"`
	PrimaryColor    string `json:"primary_color"` // hex
	ProductName     string `json:"product_name"`
	LoginPageTitle  string `json:"login_page_title"`
	LoginFooterHTML string `json:"login_footer_html"`
	CustomCSS       string `json:"custom_css"`
}

// LoginMethods — which auth methods are exposed on the portal login page.
type LoginMethods struct {
	Password         bool `json:"password"`
	SMSOTP           bool `json:"sms_otp"`
	EmailMagicLink   bool `json:"email_magic_link"`
	ExternalIdPFirst bool `json:"external_idp_first"` // show 3rd-party btns above pwd form
}

// ProtocolDefaults — boilerplate values for new app creation.
type ProtocolDefaults struct {
	OIDCAccessTokenTTLSeconds  int    `json:"oidc_access_token_ttl_seconds"`
	OIDCRefreshTokenTTLSeconds int    `json:"oidc_refresh_token_ttl_seconds"`
	OIDCIDTokenTTLSeconds      int    `json:"oidc_id_token_ttl_seconds"`
	DefaultSubjectStrategy     string `json:"default_subject_strategy"`
	SAMLAssertionTTLSeconds    int    `json:"saml_assertion_ttl_seconds"`
	CASTicketTTLSeconds        int    `json:"cas_ticket_ttl_seconds"`
}

// SMS — SMS provider config. Secret stored AES-encrypted.
type SMS struct {
	Enabled   bool   `json:"enabled"`
	Provider  string `json:"provider"` // "aliyun" | "tencent" | "twilio"
	AccessKey string `json:"access_key"`
	Secret    string `json:"secret"` // AES-encrypted at rest
	SignName  string `json:"sign_name"`
	Template  string `json:"template"` // provider-specific template ID
	Region    string `json:"region,omitempty"`
}

// OffboardingWebhook — where to notify a customer's IT/HR/ITSM system when a
// user is offboarded, so downstream accounts the SSO cutoff can't reach get a
// signed work order. Delivery is durable (via the outbox) and signed with the
// shared secret (HMAC-SHA256). Disabled by default.
type OffboardingWebhook struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Secret  string `json:"secret"` // AES-encrypted at rest; signs the payload
}

// AuditPolicy — audit log retention + notification thresholds.
type AuditPolicy struct {
	RetentionDays      int      `json:"retention_days"`
	AlertWebhookURL    string   `json:"alert_webhook_url"`
	AlertOnEventTypes  []string `json:"alert_on_event_types"`
	HighRiskRecipients []string `json:"high_risk_recipients"` // email/phone for critical events
}

// ConditionalAccess — adaptive-authentication policy. Disabled by default;
// when enabled, risk signals on a login (new country / impossible travel / new
// device) force a second factor. The engine only ever ADDS MFA — it never
// skips it (a trusted network still requires MFA).
type ConditionalAccess struct {
	Enabled                       bool `json:"enabled"`
	OnNewCountry                  bool `json:"on_new_country"`
	OnImpossibleTravel            bool `json:"on_impossible_travel"`
	OnNewDevice                   bool `json:"on_new_device"`
	ImpossibleTravelWindowMinutes int  `json:"impossible_travel_window_minutes"`
}

// MFAPolicy — multi-factor enforcement + step-up grace window.
//
// Mode governs WHO must enrol MFA (see MFAMode* consts). StepUpWindowSeconds
// is how long a passed MFA stays "fresh" for high-risk operations before a
// new step-up challenge is required (0 = challenge every time).
type MFAPolicy struct {
	Mode                string `json:"mode"`
	StepUpWindowSeconds int    `json:"step_up_window_seconds"`
}

// Localization — default language / timezone / date format.
type Localization struct {
	DefaultLanguage string `json:"default_language"` // "zh-CN" | "en-US" | ...
	DefaultTimezone string `json:"default_timezone"` // "Asia/Shanghai"
	DateFormat      string `json:"date_format"`
}

// ExternalURLs — admin-configurable canonical URLs that protocol handlers
// use when issuing redirects, building metadata, and signing tokens.
// Empty fields fall through to bootstrap.Config defaults; that fallback
// is the OSS / single-domain / dev-config baseline. Setting non-empty
// values here lets ops pin a canonical host (LAN IP, custom domain,
// reverse-proxy host) without rebuilding the binary.
type ExternalURLs struct {
	// IssuerURL is the externally-reachable OIDC issuer / SAML EntityID
	// base, e.g. "https://id.example.com". Used as the iss claim and in
	// discovery documents.
	IssuerURL string `json:"issuer_url"`
	// PortalURL is where the end-user-facing login / consent SPA lives.
	// Protocol handlers bounce unauthenticated callers here.
	PortalURL string `json:"portal_url"`
	// ConsoleURL is the admin UI base. Optional; mostly for invite emails
	// and link rewriting.
	ConsoleURL string `json:"console_url"`
}

// License — commercial license metadata. Optional in OSS builds.
type License struct {
	Key              string `json:"key"`
	RegisteredTo     string `json:"registered_to"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	MaxUsers         int    `json:"max_users"`
	MaxTenants       int    `json:"max_tenants"`
	EnableEnterprise bool   `json:"enable_enterprise"`
	// KeySet is a transient, read-only flag: whether a token is stored. Set by
	// the GET handler (which blanks Key); never trusted on write.
	KeySet bool `json:"key_set,omitempty"`
	// InstallID is this installation's fingerprint (transient, read-only). The
	// operator gives it to the vendor to request an install-bound license.
	InstallID string `json:"install_id,omitempty"`
}

/* ──────────────── Sensitive field registry ──────────────── */

// sensitiveFields lists JSON paths that MUST be AES-encrypted before save
// and decrypted on load. Keep this list authoritative — adding a new
// secret-bearing field MUST also register it here, or it leaks plaintext
// into DB.
//
// Format: "<setting_key>.<json_field>"
var sensitiveFields = map[string][]string{
	KeyMailSMTP:           {"password"},
	KeySMS:                {"secret"},
	KeyOffboardingWebhook: {"secret"},
}
