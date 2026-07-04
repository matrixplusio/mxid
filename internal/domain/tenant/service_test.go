package tenant

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&Tenant{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	return &Service{repo: NewRepository(db), idGen: idGen}
}

func TestService_CreateAndGet(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, &CreateRequest{Name: "Acme", Code: "acme"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Code != "acme" || got.Name != "Acme" {
		t.Errorf("got %+v, want code=acme name=Acme", got)
	}
}

func TestService_CreateDuplicateCode(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, &CreateRequest{Name: "A", Code: "dup"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := svc.Create(ctx, &CreateRequest{Name: "B", Code: "dup"}); !errors.Is(err, ErrTenantCodeExists) {
		t.Errorf("duplicate code: got %v, want ErrTenantCodeExists", err)
	}
}

func TestService_GetNotFound(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.Get(context.Background(), 999999); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("get missing: got %v, want ErrTenantNotFound", err)
	}
}

func TestService_LicenseQuotaBlocksCreate(t *testing.T) {
	svc := newTestService(t)
	svc.SetLicenseQuotaCheck(func(ctx context.Context) error { return ErrLicenseQuotaExceeded })
	if _, err := svc.Create(context.Background(), &CreateRequest{Name: "X", Code: "x"}); !errors.Is(err, ErrLicenseQuotaExceeded) {
		t.Errorf("quota exceeded: got %v, want ErrLicenseQuotaExceeded", err)
	}
}
