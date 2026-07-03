package group

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

func newGroupHandlerDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if err := db.AutoMigrate(&UserGroup{}, &UserGroupMember{}, &UserGroupRule{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// RemoveMember on a dynamic group must surface as 409 (membership is
// rule-derived, not directly editable) — not fall through to a bare 500.
// Mirrors AddMember's mapping of the same ErrGroupIsDynamic.
func TestHandler_RemoveMember_DynamicGroupReturns409(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newGroupHandlerDB(t)
	sys := tenantscope.SystemContext()
	if err := db.WithContext(sys).Create(&UserGroup{ID: 2, TenantID: 100, Name: "dyn", Code: "dyn", Type: TypeDynamic}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if err := db.WithContext(sys).Create(&UserGroupMember{ID: 10, GroupID: 2, UserID: 99}).Error; err != nil {
		t.Fatalf("seed member: %v", err)
	}

	svc := &Service{repo: NewRepository(db)}
	h := &Handler{service: svc}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(tenantscope.WithTenant(context.Background(), 100))
		c.Next()
	})
	r.DELETE("/groups/:id/members/:uid", h.RemoveMember)

	req := httptest.NewRequest(http.MethodDelete, "/groups/2/members/99", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("RemoveMember on dynamic group: want 409, got %d (body=%s)", w.Code, w.Body.String())
	}
}
