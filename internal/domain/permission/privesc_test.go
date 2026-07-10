package permission

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// stubBindings scripts the caller's effective permission set for authz.
type stubBindings struct{ perms map[string]struct{} }

func (s stubBindings) EffectiveBindingsForUser(context.Context, int64, int64) ([]authz.EffectiveBinding, error) {
	return []authz.EffectiveBinding{{Permissions: s.perms, ScopeType: authz.ScopeGlobal}}, nil
}

type stubAncestry struct{}

func (stubAncestry) IsAncestorOrSelf(context.Context, int64, int64) (bool, error) { return false, nil }

// A caller holding role.permission.manage must NOT be able to set a permission
// on a role that the caller does not themselves hold — otherwise a mid-level
// admin could staple `role.delete` (or any catalog perm) onto a role they
// belong to and escalate. checkSetPermissionsAllowed is the subset guard.
func TestCheckSetPermissionsAllowed_BlocksUnheldPermission(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&Role{}, &Permission{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// A normal (non super_admin) role, plus two catalog permissions.
	db.Create(&Role{ID: 100, TenantID: 1, Name: "Editor", Code: "editor", Type: 1})
	db.Create(&Permission{ID: 201, TenantID: 1, Name: "read user", Code: "user.read", Resource: "user", Action: "read"})
	db.Create(&Permission{ID: 202, TenantID: 1, Name: "delete role", Code: "role.delete", Resource: "role", Action: "delete"})

	gen, _ := snowflake.New(12)
	svc := NewService(NewGormRepository(db), gen, nil, 1)
	h := NewHandler(svc)

	// Caller holds only user.read — NOT role.delete.
	authzSvc := authz.NewService(stubBindings{perms: map[string]struct{}{"user.read": {}}}, stubAncestry{})

	newCtx := func() *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("PUT", "/roles/100/permissions", nil)
		c.Set("tenant_id", int64(1))
		c.Set("user_id", int64(5))
		c.Set(authz.CtxAuthzKey, authzSvc)
		return c
	}

	// Setting {user.read} alone is allowed (caller holds it).
	if err := h.checkSetPermissionsAllowed(newCtx(), 100, []int64{201}); err != nil {
		t.Fatalf("setting a held permission must be allowed, got %v", err)
	}

	// Setting {user.read, role.delete} must be blocked on the unheld one.
	err = h.checkSetPermissionsAllowed(newCtx(), 100, []int64{201, 202})
	if err == nil {
		t.Fatal("granting an unheld permission (role.delete) must be blocked")
	}
	if !strings.Contains(err.Error(), "role.delete") {
		t.Fatalf("block reason should name the unheld permission, got %v", err)
	}
}
