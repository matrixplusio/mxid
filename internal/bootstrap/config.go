package bootstrap

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

// Config holds all application configuration.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Redis     RedisConfig     `mapstructure:"redis"`
	Session   SessionConfig   `mapstructure:"session"`
	Security  SecurityConfig  `mapstructure:"security"`
	JWT       JWTConfig       `mapstructure:"jwt"`
	Tenant    TenantConfig    `mapstructure:"tenant"`
	Crypto    CryptoConfig    `mapstructure:"crypto"`
	GeoIP     GeoIPConfig     `mapstructure:"geoip"`
	Log       LogConfig       `mapstructure:"log"`
	Snowflake SnowflakeConfig `mapstructure:"snowflake"`
	Audit     AuditConfig     `mapstructure:"audit"`
}

type ServerConfig struct {
	Port int    `mapstructure:"port"`
	Mode string `mapstructure:"mode"`
	// AllowedOrigins is the canonical list of front-end origins permitted
	// to call the backend with credentials. Drives BOTH the CORS
	// Access-Control-Allow-Origin response AND the CSRF Origin/Referer
	// allow-list — keeping them in a single source of truth prevents the
	// classic drift where CORS gets opened up but CSRF doesn't follow.
	// Empty falls back to a localhost dev defaults (vite ports).
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	// IssuerURL is the externally-reachable root of MXID's protocol surface
	// (OIDC discovery, JWKS, SAML metadata, CAS endpoints). Returned as `iss`
	// in OIDC tokens and as EntityID in SAML metadata, so it MUST match
	// whatever client SPs are configured to expect.
	//
	// Production (single-domain deploy): same value as PortalURL, since
	// nginx routes /protocol/* to the backend on the same host. Dev: backend
	// port, e.g. http://localhost:10050.
	IssuerURL string `mapstructure:"issuer_url"`
	// PortalURL is the externally-reachable base URL of the portal SPA.
	// Used by OIDC handler to redirect users to login / consent screens.
	// Production single-domain deploy: same origin as issuer (nginx routes
	// /login and /consent to the portal SPA build). Dev: split port
	// localhost:3501 served by Vite.
	PortalURL string `mapstructure:"portal_url"`
	// ConsoleURL is the externally-reachable base URL of the admin console
	// SPA. Returned to the client by /api/v1/system/info so the in-console
	// docs page can render copy-paste-ready endpoint URLs. Optional —
	// defaults to PortalURL if blank (single-domain deploy).
	ConsoleURL string `mapstructure:"console_url"`
	// TrustedProxies lists CIDRs/IPs whose X-Forwarded-For headers the
	// router should honor when resolving client IP. Empty = gin defaults
	// (trust everything → unsafe in prod). Dev compose puts the vite
	// containers on 172.x and host gateway on 192.168.x, so we list the
	// RFC1918 ranges by default. Production should narrow this to the
	// actual edge proxy IPs.
	TrustedProxies []string `mapstructure:"trusted_proxies"`
}

// IsRelease reports whether the server is running in production ("release")
// mode. This is the single source of truth for the Mode=="release" string
// comparison scattered across bootstrap; new code MUST gate on this helper
// rather than re-comparing the raw string.
func (s ServerConfig) IsRelease() bool {
	return s.Mode == "release"
}

// DevIssuerFallback is the boot-time issuer used in debug mode, where nginx
// fronts the API on :3500 (distinct from the backend's direct port).
const DevIssuerFallback = "http://localhost:3500"

// ResolveBootIssuer picks the boot-time external issuer (OIDC `iss` / SAML
// EntityID base / CAS root) passed to the protocol handlers. Precedence:
//
//  1. envOverride (MXID_ISSUER) — explicit, wins everywhere; the dev escape
//     hatch and back-compat for deploys that already set it.
//  2. server.issuer_url — but only in release mode, where it is validated
//     non-empty and non-localhost. In debug it is intentionally ignored so the
//     nginx-fronted :3500 default holds regardless of the config template.
//  3. DevIssuerFallback (localhost:3500).
//
// The admin ExternalURLs setting still overrides the result per request via
// urlswap; this only governs the boot-time default.
func (s ServerConfig) ResolveBootIssuer(envOverride string) string {
	issuer := DevIssuerFallback
	if s.IsRelease() && s.IssuerURL != "" {
		issuer = s.IssuerURL
	}
	if envOverride != "" {
		issuer = envOverride
	}
	return issuer
}

type DatabaseConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	Name         string `mapstructure:"name"`
	User         string `mapstructure:"user"`
	Password     string `mapstructure:"password"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
	MaxIdleConns int    `mapstructure:"max_idle_conns"`
	LogLevel     string `mapstructure:"log_level"`
}

func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable TimeZone=Asia/Shanghai",
		d.Host, d.Port, d.User, d.Password, d.Name,
	)
}

// MaskedDSN returns the DSN with the password replaced by ***. Use this
// in any log line that needs to identify which database we connected to;
// the real DSN with password in clear must never reach the log stream.
func (d *DatabaseConfig) MaskedDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=*** dbname=%s",
		d.Host, d.Port, d.User, d.Name,
	)
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	DB       int    `mapstructure:"db"`
	Password string `mapstructure:"password"`
	PoolSize int    `mapstructure:"pool_size"`
}

func (r *RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

type SessionConfig struct {
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	AbsoluteTimeout time.Duration `mapstructure:"absolute_timeout"`
	CookieSecure    bool          `mapstructure:"cookie_secure"`
	CookieDomain    string        `mapstructure:"cookie_domain"`
}

type SecurityConfig struct {
	Password  PasswordConfig  `mapstructure:"password"`
	Login     LoginConfig     `mapstructure:"login"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
}

type PasswordConfig struct {
	MinLength        int  `mapstructure:"min_length"`
	RequireUppercase bool `mapstructure:"require_uppercase"`
	RequireLowercase bool `mapstructure:"require_lowercase"`
	RequireNumber    bool `mapstructure:"require_number"`
	RequireSpecial   bool `mapstructure:"require_special"`
	HistoryCount     int  `mapstructure:"history_count"`
	ExpireDays       int  `mapstructure:"expire_days"`
	ExpireWarnDays   int  `mapstructure:"expire_warn_days"`
}

type LoginConfig struct {
	MaxFailedAttempts    int           `mapstructure:"max_failed_attempts"`
	LockoutDuration      time.Duration `mapstructure:"lockout_duration"`
	CaptchaAfterFailures int           `mapstructure:"captcha_after_failures"`
}

type RateLimitConfig struct {
	Login string `mapstructure:"login"`
	API   string `mapstructure:"api"`
}

type JWTConfig struct {
	SigningAlgorithm string        `mapstructure:"signing_algorithm"`
	AccessTokenTTL   time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL  time.Duration `mapstructure:"refresh_token_ttl"`
}

type TenantConfig struct {
	DefaultID int64 `mapstructure:"default_id"`
}

// CryptoConfig groups symmetric-key material used for encrypting at-rest secrets
// (OIDC signing private keys, future Vault-backed secrets, etc).
//
// KeyEncryptionKey is a base64-encoded 32-byte (256-bit) AES master key.
// Source (priority order):
//
//  1. Env var MXID_CRYPTO_KEY_ENCRYPTION_KEY
//  2. YAML key crypto.key_encryption_key
//
// Missing or malformed key MUST cause server startup to fail fast.
//
// AuditChainKey is a base64-encoded HMAC key used by the audit Chainer to
// seal the tamper-evident hash chain (mxid_audit_entry.entry_hash). Same
// sourcing convention as KeyEncryptionKey:
//
//  1. Env var MXID_CRYPTO_AUDIT_CHAIN_KEY
//  2. YAML key crypto.audit_chain_key
//
// Missing key MUST cause server startup to fail fast in release mode; a
// malformed (non-base64) value MUST fail startup in all modes (see
// app.Run wiring) since silently running with a zero/garbage key would
// produce a chain nobody can verify.
//
// AuditAnchorKey is a base64-encoded ed25519 seed used to sign periodic
// anchors of the audit hash chain (a Merkle/rolling digest checkpoint
// written to the anchor sink — see AuditConfig). Same sourcing convention:
//
//  1. Env var MXID_CRYPTO_AUDIT_ANCHOR_KEY
//  2. YAML key crypto.audit_anchor_key
//
// Missing key MUST cause server startup to fail fast in release mode when
// audit.anchor_enabled is true (see validateSecrets), for the same reason
// as AuditChainKey: an unanchored or unverifiably-anchored chain defeats
// the tamper-evidence guarantee.
type CryptoConfig struct {
	KeyEncryptionKey string `mapstructure:"key_encryption_key"`
	AuditChainKey    string `mapstructure:"audit_chain_key"`
	AuditAnchorKey   string `mapstructure:"audit_anchor_key"`
}

// GeoIPConfig points the audit subsystem at a MaxMind GeoLite2-City
// .mmdb file. When DatabasePath is empty the audit service uses the
// NoopResolver and geo columns stay null.
type GeoIPConfig struct {
	DatabasePath string `mapstructure:"database_path"`
}

type LogConfig struct {
	Level    string `mapstructure:"level"`
	Format   string `mapstructure:"format"`
	Output   string `mapstructure:"output"`
	FilePath string `mapstructure:"file_path"`
}

type SnowflakeConfig struct {
	NodeID int64 `mapstructure:"node_id"`
}

// AuditConfig controls the audit-anchoring subsystem: periodically sealing
// a checkpoint of the tamper-evident audit hash chain (signed with
// Crypto.AuditAnchorKey) to an external sink so that even a full DB
// compromise (which could rewrite entry_hash end-to-end) is detectable
// against an out-of-band anchor.
type AuditConfig struct {
	// AnchorEnabled turns anchoring on. Defaults to true (see
	// configs/config.yaml); when true in release mode, Crypto.AuditAnchorKey
	// MUST be set (validateSecrets fails closed otherwise).
	AnchorEnabled bool `mapstructure:"anchor_enabled"`
	// AnchorSinkPath is the file the signed anchors are appended to.
	// Defaults to data/audit-anchors.log.
	AnchorSinkPath string `mapstructure:"anchor_sink_path"`
}

// LoadConfig reads configuration from file and environment variables.
func LoadConfig(configPath string) (*Config, error) {
	// Load .env into the process environment before Viper reads env overrides.
	// Best-effort: a missing .env is fine (prod injects MXID_* directly via the
	// orchestrator / secret manager). This is what lets `make dev` (air, host
	// process — no docker) pick up secrets that are intentionally absent from
	// the committed config.yaml. Existing env vars are NOT overwritten.
	_ = godotenv.Load()

	v := viper.New()

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(configPath)
	v.AddConfigPath("configs")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Load environment-specific overlay on top of the base config.yaml.
	// Selected by MXID_CONFIG_ENV (e.g. "prod" -> config.prod.yaml, "dev" ->
	// config.dev.yaml), NOT by server.mode — the gin mode (debug/release) is a
	// separate concern. A missing overlay file is fine (base config stands alone).
	if env := os.Getenv("MXID_CONFIG_ENV"); env != "" {
		v.SetConfigName("config." + env)
		_ = v.MergeInConfig()
	}

	// Environment variable overrides: MXID_DATABASE_HOST, MXID_REDIS_PORT, etc.
	v.SetEnvPrefix("MXID")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	// List-valued keys can't ride viper's AutomaticEnv (a single env var is a
	// scalar). Handle the one that matters for deployment explicitly:
	// MXID_SERVER_ALLOWED_ORIGINS="https://a,https://b" → []string. This is the
	// CORS/CSRF allow-list — the one origin setting that MUST be known at boot
	// (it gates who may even reach the console to change other settings).
	if raw := os.Getenv("MXID_SERVER_ALLOWED_ORIGINS"); raw != "" {
		cfg.Server.AllowedOrigins = splitAndTrim(raw)
	}

	if err := cfg.validateSecrets(); err != nil {
		return nil, fmt.Errorf("config secrets: %w", err)
	}

	return &cfg, nil
}

// splitAndTrim splits a comma-separated env value into a clean slice, dropping
// empty entries and surrounding whitespace.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// devDefaultDBPasswords lists passwords known to ship with the example
// configs / docker-compose. Booting prod with one of these is almost
// certainly a misconfiguration — fail fast rather than expose a public
// install with the literal "12345" example credential.
var devDefaultDBPasswords = map[string]struct{}{
	"":         {},
	"12345":    {},
	"123456":   {},
	"password": {},
	"postgres": {},
	"admin":    {},
	"root":     {},
}

// leakedDevKEKs lists key-encryption-key values that were ever committed to the
// repo (and are therefore public via git history). A release deploy booting
// with one of these is a hard failure: anyone can decrypt every OIDC signing
// key. New leaks must be appended here whenever a committed KEK is rotated out.
var leakedDevKEKs = map[string]struct{}{
	"XH76Q0Vwe81cFhXaML+fWrvAffwQCp2bwUMRofcosfI=": {},
}

// validateSecrets blocks startup when a production-mode deployment is
// running with placeholder credentials. Release-mode checks:
//   - database.password is set and not one of the dev defaults
//   - redis.password is set and not one of the dev defaults (cache holds
//     sessions/tokens — an unauthenticated prod redis is a hard no)
//   - crypto.key_encryption_key is set AND is not a value that ever leaked
//     into git history (the MasterKey loader rejects malformed base64
//     separately)
//   - crypto.audit_chain_key is set
//   - crypto.audit_anchor_key is set, when audit.anchor_enabled is true
//     (the default)
//   - session.cookie_secure is true (cookies must be Secure over the
//     public internet)
//
// Debug mode allows the placeholders so `make dev` keeps working.
func (c *Config) validateSecrets() error {
	if c.Server.Mode != "release" {
		return nil
	}
	if _, bad := devDefaultDBPasswords[strings.TrimSpace(c.Database.Password)]; bad {
		return fmt.Errorf("database.password looks like a dev placeholder; set MXID_DATABASE_PASSWORD")
	}
	if _, bad := devDefaultDBPasswords[strings.TrimSpace(c.Redis.Password)]; bad {
		return fmt.Errorf("redis.password is empty or a dev placeholder; set MXID_REDIS_PASSWORD")
	}
	kek := strings.TrimSpace(c.Crypto.KeyEncryptionKey)
	if kek == "" {
		return fmt.Errorf("crypto.key_encryption_key not set; export MXID_CRYPTO_KEY_ENCRYPTION_KEY=$(openssl rand -base64 32)")
	}
	if _, leaked := leakedDevKEKs[kek]; leaked {
		return fmt.Errorf("crypto.key_encryption_key is a value that leaked into git history; rotate it: export MXID_CRYPTO_KEY_ENCRYPTION_KEY=$(openssl rand -base64 32)")
	}
	if strings.TrimSpace(c.Crypto.AuditChainKey) == "" {
		return fmt.Errorf("crypto.audit_chain_key not set; export MXID_CRYPTO_AUDIT_CHAIN_KEY=$(openssl rand -base64 32)")
	}
	if c.Audit.AnchorEnabled {
		anchorKey := strings.TrimSpace(c.Crypto.AuditAnchorKey)
		if anchorKey == "" {
			return fmt.Errorf("crypto.audit_anchor_key not set but audit anchoring is enabled; export MXID_CRYPTO_AUDIT_ANCHOR_KEY=$(openssl rand -base64 32) or set MXID_AUDIT_ANCHOR_ENABLED=false")
		}
	}
	if !c.Session.CookieSecure {
		return fmt.Errorf("session.cookie_secure must be true in release mode (HTTPS required)")
	}
	// Fail fast on a misconfigured deployment host rather than silently degrading:
	// an empty allow-list collapses CORS/CSRF to localhost defaults, and a
	// localhost/empty issuer mints tokens with an unreachable iss.
	if len(c.Server.AllowedOrigins) == 0 {
		return fmt.Errorf("server.allowed_origins must be set in release mode; export MXID_SERVER_ALLOWED_ORIGINS")
	}
	iss := strings.TrimSpace(c.Server.IssuerURL)
	if iss == "" || strings.Contains(iss, "localhost") || strings.Contains(iss, "127.0.0.1") {
		return fmt.Errorf("server.issuer_url must be an externally-reachable URL in release mode (not empty/localhost); export MXID_SERVER_ISSUER_URL")
	}
	return nil
}
