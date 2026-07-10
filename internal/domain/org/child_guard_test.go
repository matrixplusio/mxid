package org

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

func newOrgChildGuardDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if err := db.AutoMigrate(&Organization{}, &UserOrg{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// GetMembers now excludes soft-deleted users via a subquery on mxid_user
	// (owned by the user domain, not imported here). A minimal stand-in table is
	// enough for the membership queries to resolve.
	if err := db.Exec("CREATE TABLE mxid_user (id INTEGER PRIMARY KEY, deleted_at DATETIME)").Error; err != nil {
		t.Fatalf("create mxid_user: %v", err)
	}
	return db
}

func seedOrgWithMembers(t *testing.T, db *gorm.DB) {
	t.Helper()
	sys := tenantscope.SystemContext()
	orgs := []Organization{
		{ID: 1, TenantID: 100, Name: "a-org", Code: "a", Path: "a", Extra: JSONMap{}},
		{ID: 2, TenantID: 200, Name: "b-org", Code: "b", Path: "b", Extra: JSONMap{}},
	}
	if err := db.WithContext(sys).Create(&orgs).Error; err != nil {
		t.Fatalf("seed orgs: %v", err)
	}
	if err := db.WithContext(sys).Create(&UserOrg{ID: 10, UserID: 99, OrgID: 2}).Error; err != nil {
		t.Fatalf("seed member: %v", err)
	}
	// User 99 is live (deleted_at NULL) so it counts as a member.
	if err := db.Exec("INSERT INTO mxid_user (id, deleted_at) VALUES (99, NULL)").Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// Tenant A (100) tampering :id=2 (tenant B's org) must be rejected before the
// tenant-less mxid_user_org child table is read or mutated.
func TestService_OrgChildGuard_CrossTenantBlocked(t *testing.T) {
	db := newOrgChildGuardDB(t)
	seedOrgWithMembers(t, db)
	svc := &Service{repo: NewRepository(db)}

	ctxA := tenantscope.WithTenant(context.Background(), 100)

	if _, _, err := svc.GetMembers(ctxA, 2, 1, 20); !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("GetMembers cross-tenant: got %v want ErrOrgNotFound", err)
	}
	if err := svc.AddMember(ctxA, 2, &AddMemberRequest{UserID: 77}); !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("AddMember cross-tenant: got %v want ErrOrgNotFound", err)
	}
	if err := svc.RemoveMember(ctxA, 99, 2); !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("RemoveMember cross-tenant: got %v want ErrOrgNotFound", err)
	}

	// No write leaked: tenant B's membership intact, no planted row.
	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&UserOrg{}).Where("org_id = ?", 2).Count(&count).Error; err != nil {
		t.Fatalf("count members: %v", err)
	}
	if count != 1 {
		t.Fatalf("cross-tenant op mutated tenant B org membership (count=%d)", count)
	}
}

// Same-tenant member read still resolves.
func TestService_OrgChildGuard_SameTenantAllowed(t *testing.T) {
	db := newOrgChildGuardDB(t)
	seedOrgWithMembers(t, db)
	svc := &Service{repo: NewRepository(db)}

	ctxB := tenantscope.WithTenant(context.Background(), 200)
	ids, total, err := svc.GetMembers(ctxB, 2, 1, 20)
	if err != nil {
		t.Fatalf("GetMembers same-tenant: %v", err)
	}
	if total != 1 || len(ids) != 1 || ids[0] != 99 {
		t.Fatalf("GetMembers same-tenant got ids=%v total=%d", ids, total)
	}
}

// A soft-deleted user whose mxid_user_org row lingers must NOT be counted or
// listed as an org member (defense-in-depth for a dropped UserDeleted event).
func TestService_OrgChildGuard_ExcludesSoftDeletedMember(t *testing.T) {
	db := newOrgChildGuardDB(t)
	seedOrgWithMembers(t, db)
	// Soft-delete user 99 while leaving the membership row in place.
	if err := db.Exec("UPDATE mxid_user SET deleted_at = ? WHERE id = 99", "2026-07-10 00:00:00").Error; err != nil {
		t.Fatalf("soft-delete user: %v", err)
	}
	svc := &Service{repo: NewRepository(db)}

	ctxB := tenantscope.WithTenant(context.Background(), 200)
	ids, total, err := svc.GetMembers(ctxB, 2, 1, 20)
	if err != nil {
		t.Fatalf("GetMembers: %v", err)
	}
	if total != 0 || len(ids) != 0 {
		t.Fatalf("soft-deleted user must be excluded, got ids=%v total=%d", ids, total)
	}
}
