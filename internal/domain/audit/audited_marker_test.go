package audit_test

import (
	"testing"

	"github.com/imkerbos/mxid/internal/domain/access"
	"github.com/imkerbos/mxid/internal/domain/apitoken"
	"github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/approle"
	"github.com/imkerbos/mxid/internal/domain/audit"
	"github.com/imkerbos/mxid/internal/domain/conditionalaccess"
	"github.com/imkerbos/mxid/internal/domain/oidckey"
	"github.com/imkerbos/mxid/internal/domain/permission"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/internal/domain/tenant"
	"github.com/imkerbos/mxid/internal/domain/user"
)

func TestSensitiveModelsAreAudited(t *testing.T) {
	models := []any{
		&user.User{}, &app.App{}, &approle.AppRole{},
		&permission.Role{}, &permission.Permission{}, &permission.RoleBinding{},
		&access.Request{}, &access.Eligibility{},
		&tenant.Tenant{}, &oidckey.ProviderKey{}, &apitoken.Token{},
		&setting.Setting{}, &conditionalaccess.KnownDevice{},
	}
	for _, m := range models {
		if _, ok := m.(audit.Audited); !ok {
			t.Errorf("%T must implement audit.Audited (sensitive write table not audited)", m)
		}
	}
}
