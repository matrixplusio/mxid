package group

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"gorm.io/gorm"
)

func newDynIDsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if err := db.AutoMigrate(&UserGroup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// TestListDynamicGroupIDs asserts the resync fan-out list only picks up dynamic
// (type=2) groups and stays inside the tenant — a static group or another
// tenant's dynamic group must never be dragged into a re-sync.
func TestListDynamicGroupIDs(t *testing.T) {
	db := newDynIDsDB(t)
	sys := tenantscope.SystemContext()
	seed := []UserGroup{
		{ID: 1, TenantID: 100, Name: "static-a", Code: "sa", Type: TypeStatic},
		{ID: 2, TenantID: 100, Name: "dyn-a", Code: "da", Type: TypeDynamic},
		{ID: 3, TenantID: 100, Name: "dyn-b", Code: "db", Type: TypeDynamic},
		{ID: 4, TenantID: 200, Name: "dyn-other", Code: "do", Type: TypeDynamic},
	}
	if err := db.WithContext(sys).Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	repo := NewRepository(db)
	ctx := tenantscope.WithTenant(context.Background(), 100)
	ids, err := repo.ListDynamicGroupIDs(ctx, 100)
	if err != nil {
		t.Fatalf("ListDynamicGroupIDs: %v", err)
	}

	got := map[int64]bool{}
	for _, id := range ids {
		got[id] = true
	}
	if len(ids) != 2 || !got[2] || !got[3] {
		t.Fatalf("want dynamic groups [2 3] for tenant 100, got %v", ids)
	}
	if got[1] {
		t.Error("static group 1 must not appear")
	}
	if got[4] {
		t.Error("cross-tenant dynamic group 4 must not appear")
	}
}

func TestToInt64Any(t *testing.T) {
	cases := []struct {
		in   any
		want int64
	}{
		{int64(5), 5},
		{int(7), 7},
		{float64(9), 9},
		{"nope", 0},
		{nil, 0},
	}
	for _, c := range cases {
		if got := toInt64Any(c.in); got != c.want {
			t.Errorf("toInt64Any(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}
