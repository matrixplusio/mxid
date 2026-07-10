package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// verifyStubUsers embeds UserQuerier so only the methods the verify path touches
// need real bodies; the rest stay nil (never called here).
type verifyStubUsers struct {
	UserQuerier
	curEmail string
	marked   bool
}

func (s *verifyStubUsers) GetEmail(context.Context, int64) (string, error) { return s.curEmail, nil }
func (s *verifyStubUsers) MarkEmailVerified(context.Context, int64) error  { s.marked = true; return nil }

func newVerifyHandler(t *testing.T, users UserQuerier) (*EmailVerifyHandler, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewEmailVerifyHandler(rdb, users, zap.NewNop(), "https://portal.example", nil, 1), mr
}

func doVerify(h *EmailVerifyHandler, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/profile/email/verify?token="+token, nil)
	h.verify(c)
	return w
}

// The token is bound to (userID, email). If the user changes their email after
// requesting verification, clicking the stale link must NOT flip
// email_verified — otherwise the new, unproven address gets verified for free.
func TestEmailVerify_RejectsWhenEmailChanged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	users := &verifyStubUsers{curEmail: "new@example.com"} // email changed since token issued
	h, mr := newVerifyHandler(t, users)

	// Token was issued for old@example.com.
	mr.Set(verifyKeyPrefix+"tok1", "5:old@example.com")

	w := doVerify(h, "tok1")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("stale-email link must be rejected (400), got %d", w.Code)
	}
	if users.marked {
		t.Fatal("MarkEmailVerified must NOT be called when the current email no longer matches the token")
	}
	// One-shot: token must have been consumed even on rejection.
	if mr.Exists(verifyKeyPrefix + "tok1") {
		t.Fatal("token should be consumed (deleted) after use")
	}
}

// Sanity: matching email path verifies + redirects.
func TestEmailVerify_MatchingEmailSucceeds(t *testing.T) {
	gin.SetMode(gin.TestMode)
	users := &verifyStubUsers{curEmail: "old@example.com"}
	h, mr := newVerifyHandler(t, users)
	mr.Set(verifyKeyPrefix+"tok2", "5:old@example.com")

	w := doVerify(h, "tok2")
	if w.Code != http.StatusFound {
		t.Fatalf("matching link should redirect (302), got %d", w.Code)
	}
	if !users.marked {
		t.Fatal("MarkEmailVerified must be called on a matching-email verify")
	}
}
