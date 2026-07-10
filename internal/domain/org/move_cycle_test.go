package org

import (
	"context"
	"errors"
	"testing"

	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// A Move whose new parent is the org itself or one of its descendants must be
// rejected — otherwise the ltree path becomes self-referential and the whole
// subtree is corrupted.
func TestService_Move_RejectsCycle(t *testing.T) {
	db := newOrgChildGuardDB(t)
	sys := tenantscope.SystemContext()
	orgs := []Organization{
		{ID: 1, TenantID: 200, Name: "parent", Code: "p", Path: "p", Extra: JSONMap{}},
		{ID: 2, TenantID: 200, Name: "child", Code: "c", Path: "p.c", Extra: JSONMap{}},
	}
	if err := db.WithContext(sys).Create(&orgs).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := &Service{repo: NewRepository(db)}
	ctx := tenantscope.WithTenant(context.Background(), 200)

	self := int64(1)
	if err := svc.Move(ctx, 1, &MoveOrgRequest{ParentID: &self}); !errors.Is(err, ErrOrgCycle) {
		t.Fatalf("move under self: got %v want ErrOrgCycle", err)
	}

	child := int64(2)
	if err := svc.Move(ctx, 1, &MoveOrgRequest{ParentID: &child}); !errors.Is(err, ErrOrgCycle) {
		t.Fatalf("move under own descendant: got %v want ErrOrgCycle", err)
	}
}
