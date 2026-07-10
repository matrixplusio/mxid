package permission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newPermissionReferentDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if err := db.AutoMigrate(&Role{}, &RoleBinding{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// ListMembers/CountMembers now subquery mxid_user to drop soft-deleted user
	// subjects. mxid_user is owned by the user domain (not imported here); a
	// minimal stand-in table suffices. Tests seed the rows they need live.
	if err := db.Exec("CREATE TABLE mxid_user (id INTEGER PRIMARY KEY, deleted_at DATETIME)").Error; err != nil {
		t.Fatalf("create mxid_user: %v", err)
	}
	return db
}

// seedLiveUser inserts a non-deleted mxid_user row so a user role-binding passes
// the liveUserSubject filter.
func seedLiveUser(t *testing.T, db *gorm.DB, ids ...int64) {
	t.Helper()
	for _, id := range ids {
		if err := db.Exec("INSERT INTO mxid_user (id, deleted_at) VALUES (?, NULL)", id).Error; err != nil {
			t.Fatalf("seed user %d: %v", id, err)
		}
	}
}

func testIDGen(t *testing.T) *snowflake.Generator {
	t.Helper()
	g, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	return g
}

// tenantScopedValidator mimics a tenant-scoped GetByID: an entity id "exists"
// only when its owning tenant matches the caller's tenant context.
func tenantScopedValidator(owners map[int64]int64) EntityValidator {
	return func(ctx context.Context, id int64) (bool, error) {
		owner, ok := owners[id]
		if !ok {
			return false, nil
		}
		s, _ := tenantscope.From(ctx)
		return owner == s.TenantID, nil
	}
}

func seedRole(t *testing.T, db *gorm.DB) {
	t.Helper()
	sys := tenantscope.SystemContext()
	roles := []Role{
		{ID: 1, TenantID: 100, Name: "a-role", Code: "a", Type: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	if err := db.WithContext(sys).Create(&roles).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
}

func newPermSvc(t *testing.T, db *gorm.DB) *Service {
	return &Service{
		repo:     NewGormRepository(db),
		idGen:    testIDGen(t),
		eventBus: event.NewBus(zap.NewNop()),
		tenantID: 100,
		validators: RefValidators{
			User:  tenantScopedValidator(map[int64]int64{500: 100, 999: 200}),
			Group: tenantScopedValidator(map[int64]int64{600: 100, 888: 200}),
			Org:   tenantScopedValidator(map[int64]int64{700: 100, 777: 200}),
		},
	}
}

// AddMember must reject a request-body subject id that belongs to a different
// tenant even though the parent role is owned by the caller.
func TestService_AddMember_CrossTenantSubjectRejected(t *testing.T) {
	db := newPermissionReferentDB(t)
	seedRole(t, db)
	svc := newPermSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	// Foreign user subject (tenant 200) bound to caller's role 1.
	if _, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{SubjectType: SubjectTypeUser, SubjectID: 999}); !errors.Is(err, ErrSubjectNotInTenant) {
		t.Fatalf("AddMember foreign subject: got %v want ErrSubjectNotInTenant", err)
	}
	// Foreign group subject.
	if _, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{SubjectType: SubjectTypeGroup, SubjectID: 888}); !errors.Is(err, ErrSubjectNotInTenant) {
		t.Fatalf("AddMember foreign group subject: got %v want ErrSubjectNotInTenant", err)
	}

	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&RoleBinding{}).Where("role_id = ?", 1).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("foreign subject bound to role 1 (count=%d)", count)
	}
}

// AddMember must reject a cross-tenant scope target even when the subject is
// valid.
func TestService_AddMember_CrossTenantScopeRejected(t *testing.T) {
	db := newPermissionReferentDB(t)
	seedRole(t, db)
	svc := newPermSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	foreignOrg := int64(777)
	scopeType := ScopeTypeOrg
	if _, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{
		SubjectType: SubjectTypeUser, SubjectID: 500,
		ScopeType: &scopeType, ScopeID: &foreignOrg,
	}); !errors.Is(err, ErrScopeNotInTenant) {
		t.Fatalf("AddMember foreign scope: got %v want ErrScopeNotInTenant", err)
	}
}

// A half-set scope (only ScopeType, no ScopeID) is ambiguous and must be
// rejected with the ErrScopeIncomplete sentinel — the handler needs a
// distinguishable error to map to 400 instead of falling through to 500.
func TestService_AddMember_HalfSetScopeRejected(t *testing.T) {
	db := newPermissionReferentDB(t)
	seedRole(t, db)
	svc := newPermSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	scopeType := ScopeTypeOrg
	if _, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{
		SubjectType: SubjectTypeUser, SubjectID: 500,
		ScopeType: &scopeType, ScopeID: nil,
	}); !errors.Is(err, ErrScopeIncomplete) {
		t.Fatalf("AddMember half-set scope: got %v want ErrScopeIncomplete", err)
	}
}

// Same-tenant subject (+ scope) still binds successfully.
func TestService_AddMember_SameTenantAllowed(t *testing.T) {
	db := newPermissionReferentDB(t)
	seedRole(t, db)
	svc := newPermSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	sameOrg := int64(700)
	scopeType := ScopeTypeOrg
	b, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{
		SubjectType: SubjectTypeUser, SubjectID: 500,
		ScopeType: &scopeType, ScopeID: &sameOrg,
	})
	if err != nil {
		t.Fatalf("AddMember same-tenant: %v", err)
	}
	if b == nil {
		t.Fatal("expected binding")
	}

	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&RoleBinding{}).Where("role_id = ?", 1).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("same-tenant binding not written (count=%d)", count)
	}
}
