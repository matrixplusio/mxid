package offboarding

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/domain/user"
)

// Offboarding a user that does not exist must surface as 404 — the service
// forwards user.ErrUserNotFound from the disabler, but the handler previously
// had no errors.Is discrimination and fell through to a bare 500.
func TestHandler_Offboard_UnknownUserReturns404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	d := &fakeDisabler{err: user.ErrUserNotFound}
	bus, _ := newBus(t)
	svc := NewService(d, &fakeKiller{}, fakeLookup{}, &fakeNotifier{}, nil, nil, nil, bus, zap.NewNop())
	h := NewHandler(svc, 1)

	r := gin.New()
	r.POST("/users/:id/offboard", h.Offboard)

	req := httptest.NewRequest(http.MethodPost, "/users/999/offboard", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("Offboard unknown user: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}
