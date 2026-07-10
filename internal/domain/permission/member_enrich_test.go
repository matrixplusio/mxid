package permission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

// seedNamedRole inserts a role with an explicit code so tests can target the
// reserved super_admin role and ordinary roles by id.
func seedNamedRole(t *testing.T, db *gorm.DB, id int64, code string) {
	t.Helper()
	sys := tenantscope.SystemContext()
	r := Role{ID: id, TenantID: 100, Name: code, Code: code, Type: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.WithContext(sys).Create(&r).Error; err != nil {
		t.Fatalf("seed role %q: %v", code, err)
	}
}

// fakeSuperAdminManager records flag flips and serves a member list, standing
// in for the user-domain bridge so the permission service can be tested in
// isolation.
type fakeSuperAdminManager struct {
	flags map[int64]bool // userID -> is_super_admin
}

func newFakeSAM() *fakeSuperAdminManager { return &fakeSuperAdminManager{flags: map[int64]bool{}} }

func (f *fakeSuperAdminManager) SetSuperAdmin(_ context.Context, _, _, targetID int64, makeSuper bool) error {
	f.flags[targetID] = makeSuper
	return nil
}

func (f *fakeSuperAdminManager) ListSuperAdmins(_ context.Context, _ int64) ([]SuperAdminInfo, error) {
	var out []SuperAdminInfo
	for id, on := range f.flags {
		if on {
			out = append(out, SuperAdminInfo{UserID: id, Name: "user", Secondary: ""})
		}
	}
	return out, nil
}

// Adding a user to the super_admin role must flip the is_super_admin flag (the
// role is a façade over that flag), NOT write an inert role_binding row.
// Regression for the "added user to Superadmin role but still 403" trap.
func TestService_AddMember_SuperAdminGrantsFlag(t *testing.T) {
	db := newPermissionReferentDB(t)
	seedNamedRole(t, db, 1, SuperAdminRoleCode)
	svc := newPermSvc(t, db)
	sam := newFakeSAM()
	svc.superAdmin = sam
	svc.validators.User = func(_ context.Context, _ int64) (bool, error) { return true, nil }
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	if _, err := svc.AddMember(ctxA, 7, 1, &AddMemberRequest{SubjectType: SubjectTypeUser, SubjectID: 500}); err != nil {
		t.Fatalf("AddMember super_admin: %v", err)
	}
	if !sam.flags[500] {
		t.Fatal("adding to super_admin role must set is_super_admin=true for the user")
	}
	// No inert role_binding row must be written.
	var count int64
	if err := db.WithContext(tenantscope.SystemContext()).Model(&RoleBinding{}).Where("role_id = ?", 1).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("super_admin façade must not write role_binding rows (count=%d)", count)
	}

	// Removing revokes the flag.
	if err := svc.RemoveMember(ctxA, 7, 1, 500); err != nil {
		t.Fatalf("RemoveMember super_admin: %v", err)
	}
	if sam.flags[500] {
		t.Fatal("removing from super_admin role must clear is_super_admin")
	}

	// A group subject is rejected (super-admin is per-user).
	if _, err := svc.AddMember(ctxA, 7, 1, &AddMemberRequest{SubjectType: SubjectTypeGroup, SubjectID: 600}); !errors.Is(err, ErrSuperAdminUserOnly) {
		t.Fatalf("group subject to super_admin: got %v want ErrSuperAdminUserOnly", err)
	}
}

// ListMembers on the super_admin role renders the is_super_admin users (from the
// flag manager), not role_binding rows.
func TestService_ListMembers_SuperAdminFromFlag(t *testing.T) {
	db := newPermissionReferentDB(t)
	seedNamedRole(t, db, 1, SuperAdminRoleCode)
	svc := newPermSvc(t, db)
	sam := newFakeSAM()
	sam.flags[500] = true
	sam.flags[501] = true
	svc.superAdmin = sam
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	members, total, err := svc.ListMembers(ctxA, 1, MemberListParams{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if total != 2 || len(members) != 2 {
		t.Fatalf("super_admin member list = %d want 2", total)
	}
	for _, m := range members {
		if m.SubjectType != SubjectTypeUser || m.ID != m.SubjectID {
			t.Fatalf("unexpected super_admin member row: %+v", m)
		}
	}
}

// Adding a USER subject must emit the RoleMemberAdded event carrying user_id and
// tenant_id so the authz cache does a targeted (L2-purging) Invalidate instead
// of the coarse InvalidateAll fallback. Regression for the "up to 5 min to
// refresh" bug (payload previously only had subject_id, which the subscriber
// reads under the user_id key).
func TestService_AddMember_UserSubjectEmitsUserID(t *testing.T) {
	db := newPermissionReferentDB(t)
	seedNamedRole(t, db, 1, "editor")
	svc := newPermSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	got := make(chan event.Event, 1)
	svc.eventBus.Subscribe(RoleMemberAdded, func(_ context.Context, e event.Event) { got <- e })

	if _, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{SubjectType: SubjectTypeUser, SubjectID: 500}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	select {
	case e := <-got:
		p, ok := e.Payload.(map[string]any)
		if !ok {
			t.Fatalf("payload type %T", e.Payload)
		}
		if p["user_id"] != int64(500) {
			t.Fatalf("payload user_id = %v want 500", p["user_id"])
		}
		if p["tenant_id"] != int64(100) {
			t.Fatalf("payload tenant_id = %v want 100", p["tenant_id"])
		}
	case <-time.After(time.Second):
		t.Fatal("RoleMemberAdded event not received")
	}
}

// A group subject must NOT carry user_id (it isn't a user) — the subscriber
// then correctly falls back to InvalidateAll.
func TestService_AddMember_GroupSubjectOmitsUserID(t *testing.T) {
	db := newPermissionReferentDB(t)
	seedNamedRole(t, db, 1, "editor")
	svc := newPermSvc(t, db)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	got := make(chan event.Event, 1)
	svc.eventBus.Subscribe(RoleMemberAdded, func(_ context.Context, e event.Event) { got <- e })

	if _, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{SubjectType: SubjectTypeGroup, SubjectID: 600}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	select {
	case e := <-got:
		p := e.Payload.(map[string]any)
		if _, present := p["user_id"]; present {
			t.Fatalf("group subject payload must not carry user_id: %v", p)
		}
	case <-time.After(time.Second):
		t.Fatal("RoleMemberAdded event not received")
	}
}

// ListMembers/CountMembers must exclude a role binding whose subject is a
// SOFT-DELETED user, while still keeping non-user (group) subjects — the
// liveUserSubject filter is an OR, so a naive AND would have dropped group
// bindings too.
func TestService_ListMembers_ExcludesSoftDeletedUserKeepsGroup(t *testing.T) {
	db := newPermissionReferentDB(t)
	seedNamedRole(t, db, 1, "editor")
	svc := newPermSvc(t, db)
	svc.validators.User = func(_ context.Context, _ int64) (bool, error) { return true, nil }
	svc.validators.Group = func(_ context.Context, _ int64) (bool, error) { return true, nil }
	seedLiveUser(t, db, 500, 501)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	if _, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{SubjectType: SubjectTypeUser, SubjectID: 500}); err != nil {
		t.Fatalf("AddMember user 500: %v", err)
	}
	if _, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{SubjectType: SubjectTypeUser, SubjectID: 501}); err != nil {
		t.Fatalf("AddMember user 501: %v", err)
	}
	if _, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{SubjectType: SubjectTypeGroup, SubjectID: 600}); err != nil {
		t.Fatalf("AddMember group 600: %v", err)
	}
	// Soft-delete user 501; its binding row lingers.
	if err := db.Exec("UPDATE mxid_user SET deleted_at = ? WHERE id = 501", "2026-07-10 00:00:00").Error; err != nil {
		t.Fatalf("soft-delete user: %v", err)
	}

	members, total, err := svc.ListMembers(ctxA, 1, MemberListParams{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	got := map[int64]string{}
	for _, m := range members {
		got[m.SubjectID] = m.SubjectType
	}
	if total != 2 || len(members) != 2 {
		t.Fatalf("want 2 members (live user + group), got total=%d members=%+v", total, got)
	}
	if _, ok := got[501]; ok {
		t.Fatal("soft-deleted user 501 must be excluded from role members")
	}
	if got[500] != SubjectTypeUser || got[600] != SubjectTypeGroup {
		t.Fatalf("live user + group subjects must remain: %+v", got)
	}
}

// ListMembers must resolve subject ids to display names via the injected
// resolvers, and fall back to the string id when a subject can't be resolved.
func TestService_ListMembers_ResolvesNames(t *testing.T) {
	db := newPermissionReferentDB(t)
	seedNamedRole(t, db, 1, "editor")
	svc := newPermSvc(t, db)
	svc.resolvers = SubjectResolvers{
		User: func(_ context.Context, ids []int64) (map[int64]SubjectInfo, error) {
			out := map[int64]SubjectInfo{}
			for _, id := range ids {
				if id == 500 {
					out[id] = SubjectInfo{Name: "alice", Secondary: "alice@example.com"}
				}
				// id 501 intentionally unresolved → id fallback
			}
			return out, nil
		},
	}
	// Allow any user id past the referent guard so we can seed both a
	// resolvable (500) and an unresolvable (501) subject.
	svc.validators.User = func(_ context.Context, _ int64) (bool, error) { return true, nil }
	seedLiveUser(t, db, 500, 501)
	ctxA := tenantscope.WithTenant(context.Background(), 100)

	for _, id := range []int64{500, 501} {
		if _, err := svc.AddMember(ctxA, 0, 1, &AddMemberRequest{SubjectType: SubjectTypeUser, SubjectID: id}); err != nil {
			t.Fatalf("AddMember %d: %v", id, err)
		}
	}

	members, _, err := svc.ListMembers(ctxA, 1, MemberListParams{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}

	names := map[int64]*MemberResponse{}
	for _, m := range members {
		names[m.SubjectID] = m
	}
	if m := names[500]; m == nil || m.SubjectName != "alice" || m.SubjectSecondary != "alice@example.com" {
		t.Fatalf("subject 500 not resolved: %+v", m)
	}
	if m := names[501]; m == nil || m.SubjectName != "501" {
		t.Fatalf("subject 501 should fall back to id, got %+v", m)
	}
}
