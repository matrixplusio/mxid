package bootstrap

import (
	"strings"
	"testing"
)

func TestMaskedDSN_HidesPassword(t *testing.T) {
	cfg := &DatabaseConfig{
		Host: "db.example.com", Port: 5432, User: "mxid",
		Password: "supersecret", Name: "mxid",
	}
	masked := cfg.MaskedDSN()
	if strings.Contains(masked, "supersecret") {
		t.Errorf("MaskedDSN leaked password: %s", masked)
	}
	if !strings.Contains(masked, "password=***") {
		t.Errorf("MaskedDSN should contain placeholder, got %s", masked)
	}
}

func TestValidateSecrets_DebugModeAllowsPlaceholders(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{Mode: "debug"},
		Database: DatabaseConfig{Password: "12345"},
	}
	if err := cfg.validateSecrets(); err != nil {
		t.Errorf("debug mode must permit placeholders, got %v", err)
	}
}

func TestValidateSecrets_ReleaseRejectsDevPassword(t *testing.T) {
	cases := []string{"", "12345", "password", "postgres", "admin", "root"}
	for _, pw := range cases {
		cfg := &Config{
			Server:   ServerConfig{Mode: "release"},
			Database: DatabaseConfig{Password: pw},
		}
		if err := cfg.validateSecrets(); err == nil {
			t.Errorf("release with password %q must fail", pw)
		}
	}
}

func TestValidateSecrets_ReleaseRejectsDevRedisPassword(t *testing.T) {
	cases := []string{"", "123456", "12345", "password", "admin"}
	for _, pw := range cases {
		cfg := &Config{
			Server:   ServerConfig{Mode: "release"},
			Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
			Redis:    RedisConfig{Password: pw},
			Crypto:   CryptoConfig{KeyEncryptionKey: "non-empty", AuditChainKey: "non-empty"},
			Session:  SessionConfig{CookieSecure: true},
		}
		if err := cfg.validateSecrets(); err == nil {
			t.Errorf("release with redis password %q must fail", pw)
		}
	}
}

func TestValidateSecrets_ReleaseRequiresKEK(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Mode:           "release",
			AllowedOrigins: []string{"https://id.example.com"},
			IssuerURL:      "https://id.example.com",
		},
		Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
		Redis:    RedisConfig{Password: "a-real-redis-password"},
		Crypto:   CryptoConfig{AuditChainKey: "non-empty"},
		Session:  SessionConfig{CookieSecure: true},
	}
	if err := cfg.validateSecrets(); err == nil {
		t.Errorf("missing KEK must fail in release")
	}
	cfg.Crypto.KeyEncryptionKey = "non-empty"
	cfg.Crypto.AuditAnchorKey = "non-empty"
	cfg.Audit.AnchorEnabled = true
	if err := cfg.validateSecrets(); err != nil {
		t.Errorf("release with all secrets set should pass, got %v", err)
	}
}

func TestValidateSecrets_ReleaseRequiresAuditChainKey(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Mode:           "release",
			AllowedOrigins: []string{"https://id.example.com"},
			IssuerURL:      "https://id.example.com",
		},
		Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
		Redis:    RedisConfig{Password: "a-real-redis-password"},
		Crypto:   CryptoConfig{KeyEncryptionKey: "non-empty"},
		Session:  SessionConfig{CookieSecure: true},
	}
	if err := cfg.validateSecrets(); err == nil {
		t.Errorf("missing audit chain key must fail in release")
	}
	cfg.Crypto.AuditChainKey = "non-empty"
	cfg.Crypto.AuditAnchorKey = "non-empty"
	cfg.Audit.AnchorEnabled = true
	if err := cfg.validateSecrets(); err != nil {
		t.Errorf("release with all secrets set should pass, got %v", err)
	}
}

func TestValidateSecrets_ReleaseRequiresAnchorKeyWhenEnabled(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Mode:           "release",
			AllowedOrigins: []string{"https://id.example.com"},
			IssuerURL:      "https://id.example.com",
		},
		Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
		Redis:    RedisConfig{Password: "a-real-redis-password"},
		Crypto:   CryptoConfig{KeyEncryptionKey: "non-empty", AuditChainKey: "non-empty"},
		Session:  SessionConfig{CookieSecure: true},
		Audit:    AuditConfig{AnchorEnabled: true},
	}
	if err := cfg.validateSecrets(); err == nil {
		t.Errorf("anchoring enabled with empty audit anchor key must fail in release")
	}
	cfg.Crypto.AuditAnchorKey = "non-empty"
	if err := cfg.validateSecrets(); err != nil {
		t.Errorf("release with anchor key set should pass, got %v", err)
	}
	// Disabling anchoring is a valid opt-out: no anchor key required.
	cfg.Crypto.AuditAnchorKey = ""
	cfg.Audit.AnchorEnabled = false
	if err := cfg.validateSecrets(); err != nil {
		t.Errorf("release with anchoring disabled should pass without an anchor key, got %v", err)
	}
}

func TestValidateSecrets_ReleaseRequiresOriginsAndIssuer(t *testing.T) {
	base := func() *Config {
		return &Config{
			Server: ServerConfig{
				Mode:           "release",
				AllowedOrigins: []string{"https://id.example.com"},
				IssuerURL:      "https://id.example.com",
			},
			Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
			Redis:    RedisConfig{Password: "a-real-redis-password"},
			Session:  SessionConfig{CookieSecure: true},
			Crypto:   CryptoConfig{KeyEncryptionKey: "non-empty", AuditChainKey: "non-empty", AuditAnchorKey: "non-empty"},
			Audit:    AuditConfig{AnchorEnabled: true},
		}
	}
	if err := base().validateSecrets(); err != nil {
		t.Fatalf("baseline release config should pass, got %v", err)
	}
	noOrigins := base()
	noOrigins.Server.AllowedOrigins = nil
	if err := noOrigins.validateSecrets(); err == nil {
		t.Errorf("empty allowed_origins must fail in release")
	}
	localIssuer := base()
	localIssuer.Server.IssuerURL = "http://localhost:10050"
	if err := localIssuer.validateSecrets(); err == nil {
		t.Errorf("localhost issuer_url must fail in release")
	}
}

func TestValidateSecrets_ReleaseRejectsLeakedKEK(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{Mode: "release"},
		Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
		Redis:    RedisConfig{Password: "a-real-redis-password"},
		Crypto:   CryptoConfig{KeyEncryptionKey: "XH76Q0Vwe81cFhXaML+fWrvAffwQCp2bwUMRofcosfI="},
		Session:  SessionConfig{CookieSecure: true},
	}
	if err := cfg.validateSecrets(); err == nil {
		t.Errorf("a KEK that leaked into git history must fail in release")
	}
}

// TestResolveBootIssuer locks the boot-time issuer precedence:
// MXID_ISSUER override > release server.issuer_url > localhost:3500 default.
// The release-mode arm is the deployment fix — a prod boot must issue under the
// configured domain, never the localhost placeholder.
func TestResolveBootIssuer(t *testing.T) {
	cases := []struct {
		name      string
		mode      string
		issuerURL string
		envOver   string
		want      string
	}{
		{"debug ignores config issuer, keeps localhost front", "debug", "http://localhost:10050", "", DevIssuerFallback},
		{"release uses configured issuer_url", "release", "https://id.acme.com", "", "https://id.acme.com"},
		{"release with blank issuer falls back to localhost", "release", "", "", DevIssuerFallback},
		{"MXID_ISSUER override wins in release", "release", "https://id.acme.com", "https://override.example", "https://override.example"},
		{"MXID_ISSUER override wins in debug", "debug", "", "https://override.example", "https://override.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ServerConfig{Mode: tc.mode, IssuerURL: tc.issuerURL}
			if got := s.ResolveBootIssuer(tc.envOver); got != tc.want {
				t.Errorf("ResolveBootIssuer() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateSecrets_ReleaseRequiresCookieSecure(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{Mode: "release"},
		Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
		Redis:    RedisConfig{Password: "a-real-redis-password"},
		Crypto:   CryptoConfig{KeyEncryptionKey: "non-empty", AuditChainKey: "non-empty"},
		Session:  SessionConfig{CookieSecure: false},
	}
	if err := cfg.validateSecrets(); err == nil {
		t.Errorf("CookieSecure=false in release must fail")
	}
}
