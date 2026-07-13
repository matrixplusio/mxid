package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/session"
)

// lastLoginSpy is a full UserQuerier that records the (userID, ip) handed to
// UpdateLastLogin so the passwordless-login tests can assert the stamp fired.
type lastLoginSpy struct {
	calledUser int64
	calledIP   string
	calls      int
}

func (s *lastLoginSpy) GetByID(_ context.Context, id int64) (*UserInfo, error) {
	return &UserInfo{ID: id, Username: "u", DisplayName: "U"}, nil
}
func (s *lastLoginSpy) GetDetail(context.Context, int64) (*UserDetail, error) {
	return &UserDetail{}, nil
}
func (s *lastLoginSpy) UpdateProfile(context.Context, int64, string, string, string) error { return nil }
func (s *lastLoginSpy) UpdateAvatar(context.Context, int64, string) error                  { return nil }
func (s *lastLoginSpy) ChangePassword(context.Context, int64, string, string) error        { return nil }
func (s *lastLoginSpy) MarkEmailVerified(context.Context, int64) error                     { return nil }
func (s *lastLoginSpy) GetEmail(context.Context, int64) (string, error)                    { return "", nil }
func (s *lastLoginSpy) LookupByEmail(context.Context, int64, string) (int64, error)        { return 0, nil }
func (s *lastLoginSpy) ResetPassword(context.Context, int64, string) error                 { return nil }
func (s *lastLoginSpy) LookupByPhone(context.Context, int64, string) (int64, error)        { return 0, nil }
func (s *lastLoginSpy) UpdateLastLogin(_ context.Context, id int64, ip string) error {
	s.calls++
	s.calledUser = id
	s.calledIP = ip
	return nil
}

func newSessionMgr(t *testing.T) (*session.Manager, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return session.NewManager(rdb, 30*time.Minute, 24*time.Hour), mr
}

// A successful SMS OTP login must stamp last_login_at. Passwordless logins run
// outside the password engine (which owns UpdateLastLogin in completeLogin), so
// the handler is responsible for the stamp — without it the user's "last login"
// never updates even though they logged in.
func TestSMSLogin_StampsLastLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mgr, _ := newSessionMgr(t)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	spy := &lastLoginSpy{}
	h := NewSMSOTPHandler(SMSOTPHandlerOpts{
		Redis:      rdb,
		Users:      spy,
		SessionMgr: mgr,
		DefaultTID: 1,
		Logger:     zap.NewNop(),
	})

	const phone = "13800138000"
	const uid = int64(4242)
	if err := rdb.Set(context.Background(), smsOTPKeyPrefix+phone, "4242:123456", 5*time.Minute).Err(); err != nil {
		t.Fatalf("seed code: %v", err)
	}

	r := gin.New()
	r.POST("/auth/sms/login", h.login)

	body := `{"phone":"` + phone + `","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sms/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("sms login: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if spy.calls != 1 {
		t.Fatalf("UpdateLastLogin: want 1 call, got %d", spy.calls)
	}
	if spy.calledUser != uid {
		t.Fatalf("UpdateLastLogin userID: want %d, got %d", uid, spy.calledUser)
	}
}

// A successful magic-link callback must stamp last_login_at, same rationale as
// the SMS path.
func TestMagicLinkCallback_StampsLastLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mgr, _ := newSessionMgr(t)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	spy := &lastLoginSpy{}
	h := NewMagicLinkHandler(MagicLinkHandlerOpts{
		Redis:      rdb,
		Users:      spy,
		SessionMgr: mgr,
		DefaultTID: 1,
		PortalURL:  "http://portal.test",
		Logger:     zap.NewNop(),
	})

	const token = "magic-token-abc"
	const uid = int64(7777)
	if err := rdb.Set(context.Background(), magicLinkKeyPrefix+token, "7777:1", 10*time.Minute).Err(); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	r := gin.New()
	r.GET("/auth/magic-link/callback", h.callback)

	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/callback?token="+token, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("magic callback: want 302, got %d (body=%s)", w.Code, w.Body.String())
	}
	if spy.calls != 1 {
		t.Fatalf("UpdateLastLogin: want 1 call, got %d", spy.calls)
	}
	if spy.calledUser != uid {
		t.Fatalf("UpdateLastLogin userID: want %d, got %d", uid, spy.calledUser)
	}
}
