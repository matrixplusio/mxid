package portal

// MED-D regression guard.
//
// In release mode (Server.Mode=="release", threaded in as devFallback=false)
// the forgot / magic-link / email-verify / sms-otp handlers MUST NOT leak the
// out-of-band secret (reset link / magic link / verification link / OTP code)
// into the HTTP response body OR the logs — even when the mailer / SMS provider
// is nil or returns an error. Otherwise a misconfigured production deployment
// hands the recovery secret to whoever called the endpoint, defeating the
// out-of-band delivery channel.
//
// This test drives the SMS OTP send path (representative of the four handlers,
// which share the identical `if h.devFallback { leak } else { warn-only }`
// gating) with a nil SMS provider + devFallback=false and asserts the response
// carries no dev_code and nothing sensitive is logged. The companion case with
// devFallback=true proves the dev convenience path still works in non-release.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// phoneUserStub is a minimal UserQuerier that only resolves LookupByPhone; the
// SMS send path touches nothing else.
type phoneUserStub struct{ userID int64 }

func (s phoneUserStub) GetByID(context.Context, int64) (*UserInfo, error)   { return &UserInfo{}, nil }
func (s phoneUserStub) GetDetail(context.Context, int64) (*UserDetail, error) {
	return &UserDetail{}, nil
}
func (s phoneUserStub) UpdateProfile(context.Context, int64, string, string, string) error { return nil }
func (s phoneUserStub) UpdateAvatar(context.Context, int64, string) error                  { return nil }
func (s phoneUserStub) ChangePassword(context.Context, int64, string, string) error        { return nil }
func (s phoneUserStub) MarkEmailVerified(context.Context, int64) error                     { return nil }
func (s phoneUserStub) GetEmail(context.Context, int64) (string, error)                    { return "", nil }
func (s phoneUserStub) LookupByEmail(context.Context, int64, string) (int64, error)        { return 0, nil }
func (s phoneUserStub) ResetPassword(context.Context, int64, string) error                 { return nil }
func (s phoneUserStub) LookupByPhone(context.Context, int64, string) (int64, error) {
	return s.userID, nil
}
func (s phoneUserStub) UpdateLastLogin(context.Context, int64, string) error { return nil }

func runSMSSend(t *testing.T, devFallback bool) (*smsSendResponse, *observer.ObservedLogs) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	h := NewSMSOTPHandler(SMSOTPHandlerOpts{
		Redis:       rdb,
		Users:       phoneUserStub{userID: 42},
		Logger:      logger,
		SMS:         nil, // no provider configured → fallback branch
		DefaultTID:  1,
		DevFallback: devFallback,
	})

	r := gin.New()
	r.POST("/auth/sms/send", h.send)

	body := `{"phone":"13800138000"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sms/send", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("send: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var env struct {
		Data smsSendResponse `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	return &env.Data, logs
}

// Release mode (devFallback=false): nil provider must NOT leak the OTP code in
// the body and must NOT log it.
func TestSMSSend_ReleaseModeNoDevCodeLeak(t *testing.T) {
	resp, logs := runSMSSend(t, false)

	if resp.DevCode != "" {
		t.Fatalf("release mode leaked dev_code in response: %q", resp.DevCode)
	}
	for _, e := range logs.All() {
		for _, f := range e.Context {
			if f.Key == "code" {
				t.Fatalf("release mode logged the OTP code field: %+v", e)
			}
		}
		if strings.Contains(strings.ToLower(e.Message), "fallback") &&
			!strings.Contains(strings.ToLower(e.Message), "no dev fallback") {
			t.Fatalf("release mode emitted a dev-fallback log line: %q", e.Message)
		}
	}
}

// Non-release mode (devFallback=true): the dev convenience path still surfaces
// the code so OSS / first-deploy admins can complete the flow without SMS.
func TestSMSSend_DevModeReturnsDevCode(t *testing.T) {
	resp, _ := runSMSSend(t, true)
	if resp.DevCode == "" {
		t.Fatal("dev mode should populate dev_code when no SMS provider is configured")
	}
}
