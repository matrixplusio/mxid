package org

// Regression guard: Update / Move / Create (parent_id lookup) used to fetch
// the org via a bare s.repo.GetByID call and wrap any error (including
// gorm.ErrRecordNotFound) in a plain fmt.Errorf, so the handler could never
// errors.Is-match ErrOrgNotFound and a nonexistent id/parent fell through to
// a bare 500 instead of 404. They now route through fetchOrg (same
// ErrRecordNotFound -> ErrOrgNotFound mapping requireOrg already used).

import (
	"context"
	"errors"
	"testing"

	"github.com/imkerbos/mxid/pkg/tenantscope"
)

func TestService_Update_MissingOrgReturnsErrOrgNotFound(t *testing.T) {
	db := newOrgChildGuardDB(t)
	seedOrgWithMembers(t, db)
	svc := &Service{repo: NewRepository(db)}

	ctxA := tenantscope.WithTenant(context.Background(), 100)
	_, err := svc.Update(ctxA, 999, &UpdateOrgRequest{Name: "renamed"})
	if !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("Update missing org: got %v want ErrOrgNotFound", err)
	}
}

func TestService_Move_MissingOrgReturnsErrOrgNotFound(t *testing.T) {
	db := newOrgChildGuardDB(t)
	seedOrgWithMembers(t, db)
	svc := &Service{repo: NewRepository(db)}

	ctxA := tenantscope.WithTenant(context.Background(), 100)
	err := svc.Move(ctxA, 999, &MoveOrgRequest{})
	if !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("Move missing org: got %v want ErrOrgNotFound", err)
	}
}

func TestService_Move_MissingParentReturnsErrParentOrgNotFound(t *testing.T) {
	db := newOrgChildGuardDB(t)
	seedOrgWithMembers(t, db)
	svc := &Service{repo: NewRepository(db)}

	ctxA := tenantscope.WithTenant(context.Background(), 100)
	missingParent := int64(999)
	err := svc.Move(ctxA, 1, &MoveOrgRequest{ParentID: &missingParent})
	if !errors.Is(err, ErrParentOrgNotFound) {
		t.Fatalf("Move missing parent: got %v want ErrParentOrgNotFound", err)
	}
}

func TestService_Create_MissingParentReturnsErrParentOrgNotFound(t *testing.T) {
	db := newOrgChildGuardDB(t)
	seedOrgWithMembers(t, db)
	svc := &Service{repo: NewRepository(db)}

	ctxA := tenantscope.WithTenant(context.Background(), 100)
	missingParent := int64(999)
	_, err := svc.Create(ctxA, 100, &CreateOrgRequest{Name: "child", Code: "child", ParentID: &missingParent})
	if !errors.Is(err, ErrParentOrgNotFound) {
		t.Fatalf("Create with missing parent: got %v want ErrParentOrgNotFound", err)
	}
}
