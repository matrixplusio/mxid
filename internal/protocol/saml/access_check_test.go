package saml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"go.uber.org/zap"
)

// denyChecker denies every app-access check.
type denyChecker struct{}

func (denyChecker) CheckAppAccess(_ context.Context, _, _, _ int64) (bool, string, error) {
	return false, "no-rule-matched", nil
}

// stubSessRes always resolves a valid SSO session, so processSSO reaches the
// app-access gate.
type stubSessRes struct{ sess *resolver.SSOSession }

func (s stubSessRes) GetSSOSession(context.Context, string) (*resolver.SSOSession, error) {
	return s.sess, nil
}
func (s stubSessRes) GetProtocolSSOSession(context.Context, string) (*resolver.SSOSession, error) {
	return s.sess, nil
}
func (s stubSessRes) CreateSSOSession(context.Context, int64, int64, string, string, string) (*resolver.SSOSession, error) {
	return s.sess, nil
}
func (s stubSessRes) DeleteSSOSession(context.Context, string) error { return nil }

// A denied user must NOT get an assertion: before this guard, SAML SSO minted a
// signed assertion for ANY authenticated user, ignoring the app-access policy.
func TestProcessSSO_DeniedByAccessPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	app := &resolver.AppConfig{ID: 9, TenantID: 1, Protocol: "saml", Code: "app1", Status: 1}
	appRes := resolver.NewAppResolver(
		func(context.Context, int64, string) (*resolver.AppConfig, error) { return app, nil },
		func(context.Context, int64) (*resolver.AppConfig, error) { return app, nil },
		func(context.Context, string) (*resolver.AppConfig, error) { return app, nil },
		func(context.Context, int64, string) (*resolver.CertConfig, error) { return nil, nil },
		func(context.Context, int64) ([]*resolver.CertConfig, error) { return nil, nil },
		func(context.Context) ([]*resolver.CertConfig, error) { return nil, nil },
		func(context.Context, int64) (*resolver.CertConfig, error) { return nil, nil },
	)
	sess := stubSessRes{sess: &resolver.SSOSession{ID: "s", UserID: 5, TenantID: 1}}

	h := NewHandler("https://idp.example", "", appRes, nil, sess, nil, nil, zap.NewNop())
	h.access = denyChecker{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/protocol/saml/app1/sso", nil)
	req.AddCookie(&http.Cookie{Name: "mxid_portal_sid", Value: "s"})
	c.Request = req

	// IdP-initiated (requestID == "") so the confirm step is skipped; the flow
	// reaches the app-access gate directly.
	h.processSSO(c, "app1", "", "")

	if w.Code != http.StatusForbidden {
		t.Fatalf("denied user must get 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}
