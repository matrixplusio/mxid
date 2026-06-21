package setting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

// Service wraps Repository with typed accessors, in-process cache, and
// transparent AES encryption for sensitive fields.
//
// Cache strategy: read-through with 60s TTL. Settings change rarely; 60s
// staleness across multiple backend instances is acceptable. Future could
// add Redis pub-sub invalidation if multi-node deploys need stronger
// consistency.
type Service struct {
	repo      Repository
	masterKey *crypto.MasterKey
	eventBus  *event.Bus

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// SetEventBus wires the event bus so settings changes emit a settings.updated
// audit event. Optional — a nil bus disables the emission.
func (s *Service) SetEventBus(bus *event.Bus) { s.eventBus = bus }

type cacheEntry struct {
	value     []byte
	expiresAt time.Time
}

const cacheTTL = 60 * time.Second

// ErrNotFound — distinguishable from generic errors so callers can fall
// back to defaults gracefully.
var ErrNotFound = errors.New("setting not found")

func NewService(repo Repository, masterKey *crypto.MasterKey) *Service {
	return &Service{
		repo:      repo,
		masterKey: masterKey,
		cache:     make(map[string]cacheEntry),
	}
}

/* ──────────────── Generic Get / Set ──────────────── */

// Get reads and decodes a setting into target. Returns ErrNotFound when
// the row doesn't exist (caller should use category-specific Default*).
// Decrypts sensitive fields automatically.
func (s *Service) Get(ctx context.Context, key string, tenantID int64, target any) error {
	raw, err := s.getRaw(ctx, key, tenantID)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("decode setting %s: %w", key, err)
	}
	return s.decryptSensitive(key, target)
}

// Set encrypts sensitive fields, marshals, and persists.
func (s *Service) Set(ctx context.Context, key string, tenantID int64, value any, updatedBy *int64) error {
	// Encrypt sensitive fields on a deep copy so the caller's struct stays
	// readable in plaintext.
	toStore, err := s.encryptSensitive(key, value)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(toStore)
	if err != nil {
		return fmt.Errorf("encode setting %s: %w", key, err)
	}
	if err := s.repo.Upsert(ctx, &Setting{
		Key:       key,
		TenantID:  tenantID,
		Value:     raw,
		UpdatedBy: updatedBy,
	}); err != nil {
		return err
	}
	s.invalidate(key, tenantID)

	// Emit a settings.updated audit event carrying which section changed.
	// Actor / IP are denormalized downstream from the request-scoped auditctx;
	// actor_id is also passed explicitly from the updatedBy argument.
	if s.eventBus != nil {
		payload := map[string]any{"section": key, "tenant_id": tenantID}
		if updatedBy != nil {
			payload["actor_id"] = *updatedBy
		}
		s.eventBus.Publish(ctx, event.Event{Type: event.SettingsUpdated, Payload: payload})
	}
	return nil
}

func (s *Service) getRaw(ctx context.Context, key string, tenantID int64) ([]byte, error) {
	cacheKey := cacheKeyFor(key, tenantID)

	s.mu.RLock()
	if e, ok := s.cache[cacheKey]; ok && time.Now().Before(e.expiresAt) {
		s.mu.RUnlock()
		return e.value, nil
	}
	s.mu.RUnlock()

	// System/pre-auth reads (login, bootstrap, boot) carry an explicit tenantID
	// but no ctx scope. Setting reads are always tenant-explicit, so a missing
	// scope is NOT a tenant-isolation hole — scope to the requested tenant so the
	// tenantscope plugin doesn't fail closed. Existing scope (incl. CrossTenant /
	// System escapes) is left untouched. Single root-cause fix for every pre-auth
	// setting read (login providers, bootstrap, conditional-access, ...).
	if _, ok := tenantscope.From(ctx); !ok {
		ctx = tenantscope.WithTenant(ctx, tenantID)
	}

	row, err := s.repo.Get(ctx, key, tenantID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	s.mu.Lock()
	s.cache[cacheKey] = cacheEntry{value: row.Value, expiresAt: time.Now().Add(cacheTTL)}
	s.mu.Unlock()

	return row.Value, nil
}

func (s *Service) invalidate(key string, tenantID int64) {
	s.mu.Lock()
	delete(s.cache, cacheKeyFor(key, tenantID))
	s.mu.Unlock()
}

func cacheKeyFor(key string, tenantID int64) string {
	return fmt.Sprintf("%s|%d", key, tenantID)
}

/* ──────────────── Sensitive field crypto ──────────────── */

// encryptSensitive returns a value with marked fields encrypted. Works by
// round-tripping through map[string]any so we can manipulate nested keys
// without reflection-heavy code.
func (s *Service) encryptSensitive(key string, value any) (any, error) {
	fields := sensitiveFields[key]
	if len(fields) == 0 {
		return value, nil
	}
	asJSON, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(asJSON, &m); err != nil {
		return nil, err
	}
	for _, f := range fields {
		v, ok := m[f].(string)
		if !ok || v == "" {
			continue
		}
		enc, err := s.masterKey.Encrypt([]byte(v))
		if err != nil {
			return nil, fmt.Errorf("encrypt %s.%s: %w", key, f, err)
		}
		m[f] = "enc:" + enc
	}
	return m, nil
}

// decryptSensitive walks the target (must be pointer-to-struct) and
// decrypts marked fields. Uses JSON round-trip to keep code generic.
func (s *Service) decryptSensitive(key string, target any) error {
	fields := sensitiveFields[key]
	if len(fields) == 0 {
		return nil
	}
	// Round-trip through map to find / decrypt fields, then unmarshal back.
	asJSON, err := json.Marshal(target)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(asJSON, &m); err != nil {
		return err
	}
	mutated := false
	for _, f := range fields {
		v, ok := m[f].(string)
		if !ok {
			continue
		}
		if len(v) >= 4 && v[:4] == "enc:" {
			plain, err := s.masterKey.Decrypt(v[4:])
			if err != nil {
				return fmt.Errorf("decrypt %s.%s: %w", key, f, err)
			}
			m[f] = string(plain)
			mutated = true
		}
	}
	if !mutated {
		return nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

/* ──────────────── Defaults ──────────────── */

// DefaultMailSMTP returns reasonable empty defaults. Real SMTP config
// must be set by admin before any mail is sent (mailer.Send checks Enabled).
func DefaultMailSMTP() MailSMTP {
	return MailSMTP{
		Enabled:     false,
		Port:        587,
		TLSMode:     "starttls",
		FromName:    "MXID",
		FromAddress: "noreply@example.com",
	}
}

func DefaultMailTemplates() MailTemplates {
	return MailTemplates{
		EmailVerify: MailTemplate{
			Subject: "[MXID] 请验证您的邮箱",
			Body:    `<p>您好 {{.User.DisplayName}}，</p><p>请点击下方链接验证您的邮箱：</p><p><a href="{{.Link}}">{{.Link}}</a></p><p>链接 30 分钟内有效。</p>`,
		},
		PasswordReset: MailTemplate{
			Subject: "[MXID] 重置密码",
			Body:    `<p>请点击下方链接重置密码：</p><p><a href="{{.Link}}">{{.Link}}</a></p>`,
		},
		Welcome: MailTemplate{
			Subject: "[MXID] 欢迎加入",
			Body:    `<p>您好 {{.User.DisplayName}}，欢迎加入！</p>`,
		},
		MagicLink: MailTemplate{
			Subject: "[MXID] 一键登录链接",
			Body:    `<p>您好，请点击下方链接登录，链接 5 分钟内有效：</p><p><a href="{{.Link}}">{{.Link}}</a></p><p>若非本人操作，请忽略本邮件。</p>`,
		},
	}
}

func DefaultSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		Password: PasswordPolicy{
			MinLength: 8, RequireUppercase: true, RequireLowercase: true,
			RequireNumber: true, RequireSpecial: false,
			HistoryCount: 5, ExpireDays: 90, ExpireWarnDays: 7,
		},
		Login: LoginPolicy{
			MaxFailedAttempts: 5, LockoutMinutes: 15, CaptchaAfterFailures: 3,
		},
		Session: SessionPolicy{
			IdleMinutes: 480, AbsoluteHours: 24, RememberMeHours: 168,
		},
	}
}

func DefaultBranding() Branding {
	return Branding{
		ProductName:  "MXID",
		PrimaryColor: "#2563eb",
	}
}

func DefaultLoginMethods() LoginMethods {
	return LoginMethods{Password: true, SMSOTP: false, EmailMagicLink: false}
}

func DefaultProtocolDefaults() ProtocolDefaults {
	return ProtocolDefaults{
		OIDCAccessTokenTTLSeconds:  900,
		OIDCRefreshTokenTTLSeconds: 604800,
		OIDCIDTokenTTLSeconds:      900,
		DefaultSubjectStrategy:     "persistent_id",
		SAMLAssertionTTLSeconds:    28800,
		CASTicketTTLSeconds:        60,
	}
}

func DefaultSMS() SMS                               { return SMS{Enabled: false} }
func DefaultOffboardingWebhook() OffboardingWebhook { return OffboardingWebhook{} }
func DefaultAuditPolicy() AuditPolicy {
	return AuditPolicy{RetentionDays: 365}
}
func DefaultLocalization() Localization {
	return Localization{DefaultLanguage: "zh-CN", DefaultTimezone: "Asia/Shanghai"}
}
func DefaultLicense() License { return License{} }

// DefaultMFAPolicy: off by default (opt-in so an upgrade never locks anyone
// out) with a 30-minute step-up grace window.
func DefaultMFAPolicy() MFAPolicy {
	return MFAPolicy{Mode: MFAModeOff, StepUpWindowSeconds: 1800}
}

// DefaultConditionalAccess: disabled by default (opt-in); 60-minute
// impossible-travel window.
func DefaultConditionalAccess() ConditionalAccess {
	return ConditionalAccess{ImpossibleTravelWindowMinutes: 60}
}

// DefaultExternalURLs returns empty values. Empty = fall through to
// bootstrap.Config defaults in handlers.
func DefaultExternalURLs() ExternalURLs { return ExternalURLs{} }

/* ──────────────── Typed convenience accessors ──────────────── */

func (s *Service) MailSMTP(ctx context.Context, tenantID int64) (MailSMTP, error) {
	v := DefaultMailSMTP()
	err := s.Get(ctx, KeyMailSMTP, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

func (s *Service) SecurityPolicy(ctx context.Context, tenantID int64) (SecurityPolicy, error) {
	v := DefaultSecurityPolicy()
	err := s.Get(ctx, KeySecurityPolicy, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

func (s *Service) Branding(ctx context.Context, tenantID int64) (Branding, error) {
	v := DefaultBranding()
	err := s.Get(ctx, KeyBranding, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

func (s *Service) SMS(ctx context.Context, tenantID int64) (SMS, error) {
	v := DefaultSMS()
	err := s.Get(ctx, KeySMS, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

func (s *Service) ExternalURLs(ctx context.Context, tenantID int64) (ExternalURLs, error) {
	v := DefaultExternalURLs()
	err := s.Get(ctx, KeyExternalURLs, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

func (s *Service) AuditPolicy(ctx context.Context, tenantID int64) (AuditPolicy, error) {
	v := DefaultAuditPolicy()
	err := s.Get(ctx, KeyAuditPolicy, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

// OffboardingWebhook returns the configured offboarding webhook (decrypted
// secret). Disabled-by-default when unset.
func (s *Service) OffboardingWebhook(ctx context.Context, tenantID int64) (OffboardingWebhook, error) {
	v := DefaultOffboardingWebhook()
	err := s.Get(ctx, KeyOffboardingWebhook, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

func (s *Service) MFAPolicy(ctx context.Context, tenantID int64) (MFAPolicy, error) {
	v := DefaultMFAPolicy()
	err := s.Get(ctx, KeyMFAPolicy, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

func (s *Service) ConditionalAccess(ctx context.Context, tenantID int64) (ConditionalAccess, error) {
	v := DefaultConditionalAccess()
	err := s.Get(ctx, KeyConditionalAccess, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

// License moved to internal/domain/platformconfig — the license token is a
// platform-level singleton, not tenant-scoped config. See platformconfig.Service.

func (s *Service) ProtocolDefaults(ctx context.Context, tenantID int64) (ProtocolDefaults, error) {
	v := DefaultProtocolDefaults()
	err := s.Get(ctx, KeyProtocolDefault, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

func (s *Service) LoginMethods(ctx context.Context, tenantID int64) (LoginMethods, error) {
	v := DefaultLoginMethods()
	err := s.Get(ctx, KeyLoginMethods, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

func (s *Service) Localization(ctx context.Context, tenantID int64) (Localization, error) {
	v := DefaultLocalization()
	err := s.Get(ctx, KeyLocalization, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}

func (s *Service) MailTemplates(ctx context.Context, tenantID int64) (MailTemplates, error) {
	v := DefaultMailTemplates()
	err := s.Get(ctx, KeyMailTemplates, tenantID, &v)
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	return v, err
}
