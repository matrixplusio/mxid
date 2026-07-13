package portal

// Regression guard for the password-reset status-code mapping.
//
// h.reset used to discriminate user.Service.ResetPassword's errors with a
// fragile `strings.Contains(err.Error(), "password")` heuristic. That heuristic
// had it backwards in two ways:
//   - user.ErrUserNotFound ("user not found") has no "password" substring, so
//     a user deleted between /password/forgot and /password/reset fell through
//     to a bare 500 instead of a 400.
//   - any unrelated 500-worthy failure whose message happens to mention
//     "password" (e.g. a DB write failure inside UpdatePassword) would be
//     misclassified as a 400 validation error, hiding a real outage.
//
// These tests drive the handler through errors.Is on the real sentinels and
// assert the corrected status in both directions.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/user"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// resetPasswordStub is a minimal UserQuerier whose ResetPassword returns a
// configurable error, standing in for user.Service.ResetPassword's sentinels.
type resetPasswordStub struct{ resetErr error }

func (s resetPasswordStub) GetByID(context.Context, int64) (*UserInfo, error) {
	return &UserInfo{}, nil
}
func (s resetPasswordStub) GetDetail(context.Context, int64) (*UserDetail, error) {
	return &UserDetail{}, nil
}
func (s resetPasswordStub) UpdateProfile(context.Context, int64, string, string, string) error {
	return nil
}
func (s resetPasswordStub) UpdateAvatar(context.Context, int64, string) error           { return nil }
func (s resetPasswordStub) ChangePassword(context.Context, int64, string, string) error { return nil }
func (s resetPasswordStub) MarkEmailVerified(context.Context, int64) error              { return nil }
func (s resetPasswordStub) GetEmail(context.Context, int64) (string, error)             { return "", nil }
func (s resetPasswordStub) LookupByEmail(context.Context, int64, string) (int64, error) {
	return 0, nil
}
func (s resetPasswordStub) ResetPassword(context.Context, int64, string) error { return s.resetErr }
func (s resetPasswordStub) LookupByPhone(context.Context, int64, string) (int64, error) {
	return 0, nil
}
func (s resetPasswordStub) UpdateLastLogin(context.Context, int64, string) error { return nil }

func newResetHandler(t *testing.T, resetErr error) (*PasswordResetHandler, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	h := NewPasswordResetHandler(rdb, resetPasswordStub{resetErr: resetErr}, zap.NewNop(), "https://portal.example", nil, 1, nil)
	return h, rdb
}

func seedResetToken(t *testing.T, rdb *redis.Client, token string, tenantID, userID int64) {
	t.Helper()
	val := fmt.Sprintf("%d:%d", tenantID, userID)
	if err := rdb.Set(context.Background(), pwdResetKeyPrefix+token, val, time.Hour).Err(); err != nil {
		t.Fatalf("seed token: %v", err)
	}
}

func doReset(t *testing.T, h *PasswordResetHandler, token string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/password/reset", h.reset)
	body := fmt.Sprintf(`{"token":%q,"new_password":"Sup3rSecret!"}`, token)
	req := httptest.NewRequest(http.MethodPost, "/password/reset", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestReset_UserNotFoundReturns400(t *testing.T) {
	h, rdb := newResetHandler(t, user.ErrUserNotFound)
	seedResetToken(t, rdb, "tok1", 1, 42)

	w := doReset(t, h, "tok1")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ResetPassword ErrUserNotFound: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestReset_WeakPasswordReturns400(t *testing.T) {
	h, rdb := newResetHandler(t, fmt.Errorf("%w: needs an uppercase letter", user.ErrWeakPassword))
	seedResetToken(t, rdb, "tok2", 1, 42)

	w := doReset(t, h, "tok2")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ResetPassword ErrWeakPassword: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestReset_PasswordReusedReturns400(t *testing.T) {
	h, rdb := newResetHandler(t, user.ErrPasswordReused)
	seedResetToken(t, rdb, "tok3", 1, 42)

	w := doReset(t, h, "tok3")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ResetPassword ErrPasswordReused: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestReset_UnrelatedErrorContainingPasswordSubstringReturns500(t *testing.T) {
	h, rdb := newResetHandler(t, fmt.Errorf("update password: connection refused"))
	seedResetToken(t, rdb, "tok4", 1, 42)

	w := doReset(t, h, "tok4")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("ResetPassword unrelated infra error: want 500, got %d (body=%s)", w.Code, w.Body.String())
	}
}
