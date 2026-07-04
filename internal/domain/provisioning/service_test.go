package provisioning

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/crypto"
	"gorm.io/gorm"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&Config{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mk, err := crypto.NewMasterKey(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("master key: %v", err)
	}
	return NewService(NewRepository(db), mk)
}

func TestService_GetUnsetReturnsDisabledDefault(t *testing.T) {
	svc := newTestService(t)
	v, err := svc.Get(context.Background(), 42)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if v.AppID != 42 || v.Enabled || v.TokenSet || v.Connector != ConnectorSCIM2 {
		t.Errorf("unset get = %+v, want disabled scim2 default", v)
	}
}

func TestService_SaveAndGetRoundTrip(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if err := svc.Save(ctx, SaveInput{AppID: 7, TenantID: 1, Enabled: true, BaseURL: "https://scim.example.com", Token: "secret-token"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	v, err := svc.Get(ctx, 7)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !v.Enabled || !v.TokenSet || v.BaseURL != "https://scim.example.com" {
		t.Errorf("get after save = %+v", v)
	}
	if !svc.Enabled(ctx, 7) {
		t.Error("Enabled() should report true")
	}
}

func TestService_ResolvedDecryptsToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if err := svc.Save(ctx, SaveInput{AppID: 9, Enabled: true, BaseURL: "https://x", Token: "tok-123"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	enabled, _, baseURL, token, err := svc.Resolved(ctx, 9)
	if err != nil {
		t.Fatalf("resolved: %v", err)
	}
	if !enabled || baseURL != "https://x" || token != "tok-123" {
		t.Errorf("resolved = enabled:%v base:%q token:%q, want token round-trip", enabled, baseURL, token)
	}
}

func TestService_SaveBlankTokenKeepsExisting(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if err := svc.Save(ctx, SaveInput{AppID: 5, Enabled: true, BaseURL: "https://y", Token: "keep-me"}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	// Second save omits the token — must preserve the previously stored one.
	if err := svc.Save(ctx, SaveInput{AppID: 5, Enabled: true, BaseURL: "https://y2"}); err != nil {
		t.Fatalf("second save: %v", err)
	}
	_, _, _, token, err := svc.Resolved(ctx, 5)
	if err != nil {
		t.Fatalf("resolved: %v", err)
	}
	if token != "keep-me" {
		t.Errorf("blank-token save should keep existing token, got %q", token)
	}
}
