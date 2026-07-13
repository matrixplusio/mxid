package portal

// Regression guard: updateProfile used to call UserQuerier.UpdateProfile,
// whose (real) implementation bypasses user.Service.Update's duplicate
// email/phone validation, writing straight through the repo. A duplicate
// value there hits the DB's unique constraint and previously surfaced as an
// undiscriminated error -> InternalError (500). It must map to 409 the same
// way the console admin-edit path (user.Handler.handleServiceError) does.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/domain/user"
)

type updateProfileStub struct{ updateErr error }

func (s updateProfileStub) GetByID(context.Context, int64) (*UserInfo, error) {
	return &UserInfo{}, nil
}
func (s updateProfileStub) GetDetail(context.Context, int64) (*UserDetail, error) {
	return &UserDetail{}, nil
}
func (s updateProfileStub) UpdateProfile(context.Context, int64, string, string, string) error {
	return s.updateErr
}
func (s updateProfileStub) UpdateAvatar(context.Context, int64, string) error           { return nil }
func (s updateProfileStub) ChangePassword(context.Context, int64, string, string) error { return nil }
func (s updateProfileStub) MarkEmailVerified(context.Context, int64) error              { return nil }
func (s updateProfileStub) GetEmail(context.Context, int64) (string, error)             { return "", nil }
func (s updateProfileStub) LookupByEmail(context.Context, int64, string) (int64, error) {
	return 0, nil
}
func (s updateProfileStub) ResetPassword(context.Context, int64, string) error { return nil }
func (s updateProfileStub) LookupByPhone(context.Context, int64, string) (int64, error) {
	return 0, nil
}
func (s updateProfileStub) UpdateLastLogin(context.Context, int64, string) error { return nil }

func doUpdateProfile(t *testing.T, updateErr error) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := NewProfileHandler(updateProfileStub{updateErr: updateErr}, nil)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(authn.CtxUserID, int64(1))
		c.Next()
	})
	r.PUT("/profile", h.updateProfile)

	body := `{"display_name":"Alice","phone":"","email":"dup@example.com"}`
	req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestUpdateProfile_DuplicateEmailReturns409(t *testing.T) {
	w := doUpdateProfile(t, user.ErrEmailExists)
	if w.Code != http.StatusConflict {
		t.Fatalf("UpdateProfile ErrEmailExists: want 409, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestUpdateProfile_DuplicatePhoneReturns409(t *testing.T) {
	w := doUpdateProfile(t, user.ErrPhoneExists)
	if w.Code != http.StatusConflict {
		t.Fatalf("UpdateProfile ErrPhoneExists: want 409, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestUpdateProfile_OtherErrorStaysInternalError(t *testing.T) {
	w := doUpdateProfile(t, context.DeadlineExceeded)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("UpdateProfile unrelated error: want 500, got %d (body=%s)", w.Code, w.Body.String())
	}
}
