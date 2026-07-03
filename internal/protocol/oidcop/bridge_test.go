package oidcop

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// fakeBridgeAppResolver resolves a single first-party app. onGetApp, if set,
// runs before the app is returned — used to simulate the auth request
// expiring/being deleted concurrently between the initial AuthRequestByID
// lookup (bridge.go:74) and the later AuthRequestDone call (bridge.go:117),
// which is the externally-triggerable race the fix covers.
type fakeBridgeAppResolver struct {
	resolver.AppResolver
	app      *resolver.AppConfig
	onGetApp func()
}

func (f *fakeBridgeAppResolver) GetAppByClientID(_ context.Context, _ string) (*resolver.AppConfig, error) {
	if f.onGetApp != nil {
		f.onGetApp()
	}
	return f.app, nil
}

type fakeBridgeSessionResolver struct {
	resolver.SessionResolver
	sess *resolver.SSOSession
}

func (f *fakeBridgeSessionResolver) GetSSOSession(_ context.Context, _ string) (*resolver.SSOSession, error) {
	return f.sess, nil
}

// TestLoginBridgeHandle_AuthRequestExpiredDuringCompletion proves that when
// AuthRequestDone (bridge.go:117) fails because the auth request vanished
// between the initial lookup and completion (e.g. it expired mid-flight — an
// externally triggerable race, since the auth request TTL is attacker/
// client-controlled by how long they sit on the login page), Handle now
// mirrors the bridge.go:74-78 "unknown or expired auth request" 400 response
// instead of the previous unconditional 500.
func TestLoginBridgeHandle_AuthRequestExpiredDuringCompletion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storage := NewStorage(rdb, nil, nil, nil, DefaultConfig())

	ctx := context.Background()
	req, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "app1",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       []string{"openid"},
		ResponseType: oidc.ResponseTypeCode,
	}, "")
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}
	authReqID := req.GetID()

	app := &resolver.AppConfig{
		ID:             1,
		ClientID:       "app1",
		Protocol:       "oidc",
		Status:         1,
		FirstParty:     true,
		RequireConsent: false,
	}
	apps := &fakeBridgeAppResolver{
		app: app,
		// Simulate the race: the auth request expires/is deleted right after
		// Handle's initial AuthRequestByID succeeded, but before it reaches
		// AuthRequestDone.
		onGetApp: func() {
			if err := storage.DeleteAuthRequest(ctx, authReqID); err != nil {
				t.Fatalf("DeleteAuthRequest: %v", err)
			}
		},
	}
	sessions := &fakeBridgeSessionResolver{sess: &resolver.SSOSession{
		ID:        "sess1",
		UserID:    42,
		TenantID:  1,
		AuthType:  "pwd",
		ExpiresAt: time.Now().Add(time.Hour),
	}}

	bridge := NewLoginBridge(storage, apps, sessions, nil,
		func(context.Context, string) string { return "https://issuer.example.com/callback" },
		func(id string) string { return "https://issuer.example.com/login?authRequestID=" + id },
		"https://portal.example.com",
	)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	httpReq := httptest.NewRequest(http.MethodGet, "/protocol/oidc/login?authRequestID="+authReqID, nil)
	httpReq.AddCookie(&http.Cookie{Name: "mxid_proto_sid", Value: "sess1"})
	c.Request = httpReq

	bridge.Handle(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %q)", w.Code, http.StatusBadRequest, w.Body.String())
	}
}
