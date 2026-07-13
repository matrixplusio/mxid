package app

import (
	"context"
	"errors"
	"testing"

	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// A form-fill (SWA) app is an EE capability. In CE (no license) creating one must
// be rejected — the credential vault must not exist without the form_fill feature.
func TestService_CreateForm_RequiresLicense(t *testing.T) {
	db := newAppChildGuardDB(t)
	svc := &Service{repo: NewGormRepository(db), idGen: testIDGen(t)}
	ctx := tenantscope.WithTenant(context.Background(), 100)

	// license.Current() defaults to the CE manager (no features) in a unit test,
	// so the form_fill gate is closed.
	if _, err := svc.Create(ctx, 100, &CreateAppRequest{
		Name:     "Legacy Wiki",
		Code:     "legacy-wiki-form",
		Protocol: ProtocolForm,
	}); !errors.Is(err, ErrFormFillNotLicensed) {
		t.Fatalf("Create form in CE: got %v, want ErrFormFillNotLicensed", err)
	}
}
