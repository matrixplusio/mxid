package portal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/imkerbos/mxid/internal/domain/apitoken"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/domain/user"
)

// withUser injects an authenticated user id into the gin context the way the
// real auth middleware does, so handlers under test see authn.GetUserID ok.
func withUser(userID int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(authn.CtxUserID, userID)
		c.Next()
	}
}

// --- revokeAPIToken -> 404 on apitoken.ErrNotFound ---

type fakeAPITokenQuerier struct {
	revokeErr error
}

func (f fakeAPITokenQuerier) List(context.Context, int64) ([]*APITokenInfo, error) { return nil, nil }
func (f fakeAPITokenQuerier) Create(context.Context, int64, int64, string, []string, int) (*APITokenInfo, error) {
	return nil, nil
}
func (f fakeAPITokenQuerier) Revoke(context.Context, int64, int64) error { return f.revokeErr }

func TestRevokeAPIToken_NotFoundReturns404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &SecurityHandler{apiTokenQuerier: fakeAPITokenQuerier{revokeErr: apitoken.ErrNotFound}}

	r := gin.New()
	r.Use(withUser(1))
	r.DELETE("/security/api-tokens/:id", h.revokeAPIToken)

	req := httptest.NewRequest(http.MethodDelete, "/security/api-tokens/999", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown token: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// --- setupTOTP -> 409 on user.ErrMFAAlreadyExists ---

type fakeMFAQuerier struct {
	setupErr error
}

func (f fakeMFAQuerier) ListMFA(context.Context, int64) ([]*MFAInfo, error) { return nil, nil }
func (f fakeMFAQuerier) SetupTOTP(context.Context, int64) (string, string, error) {
	return "", "", f.setupErr
}
func (f fakeMFAQuerier) VerifyTOTP(context.Context, int64, string) error { return nil }
func (f fakeMFAQuerier) DeleteTOTP(context.Context, int64) error        { return nil }
func (f fakeMFAQuerier) GenerateBackupCodes(context.Context, int64) ([]string, error) {
	return nil, nil
}
func (f fakeMFAQuerier) CountBackupCodes(context.Context, int64) (int, error) { return 0, nil }

func TestSetupTOTP_AlreadyEnrolledReturns409(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &SecurityHandler{mfaQuerier: fakeMFAQuerier{setupErr: user.ErrMFAAlreadyExists}}

	r := gin.New()
	r.Use(withUser(1))
	r.POST("/security/totp/setup", h.setupTOTP)

	req := httptest.NewRequest(http.MethodPost, "/security/totp/setup", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("setupTOTP already enrolled: want 409, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// --- launchApp -> 404 on gorm.ErrRecordNotFound ---

type fakeAppQuerier struct {
	launchErr error
}

func (f fakeAppQuerier) ListAuthorizedApps(context.Context, int64, int64, string) ([]*AppInfo, error) {
	return nil, nil
}
func (f fakeAppQuerier) GetAppLaunchURL(context.Context, int64, int64) (string, error) {
	return "", f.launchErr
}
func (f fakeAppQuerier) AppName(context.Context, int64) (string, error) { return "", nil }
func (f fakeAppQuerier) ListAuthorizedAppGroups(context.Context, int64, int64) ([]*AppGroupInfo, error) {
	return nil, nil
}
func (f fakeAppQuerier) ListFavoriteAppIDs(context.Context, int64) ([]int64, error) { return nil, nil }
func (f fakeAppQuerier) AddFavorite(context.Context, int64, int64, int64) error     { return nil }
func (f fakeAppQuerier) RemoveFavorite(context.Context, int64, int64) error         { return nil }
func (f fakeAppQuerier) ReorderFavorites(context.Context, int64, []int64) error     { return nil }
func (f fakeAppQuerier) ListRecentAppIDs(context.Context, int64, int64, int) ([]int64, error) {
	return nil, nil
}

func TestLaunchApp_DeletedAppReturns404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &appsHandler{appQuerier: fakeAppQuerier{launchErr: fmt.Errorf("get app by id: %w", gorm.ErrRecordNotFound)}}

	r := gin.New()
	r.Use(withUser(1))
	r.GET("/apps/:id/launch", h.launchApp)

	req := httptest.NewRequest(http.MethodGet, "/apps/42/launch", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("launchApp deleted app: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}
