package approle

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the app-role domain. response.MapError renders a bound
// sentinel with its safe message; any unbound error (a wrapped DB failure, a
// "validator not configured" server misconfig) becomes a logged 500 that never
// leaks internals. The former handler funnelled every service error through a
// single 40003 + err.Error(), which both leaked wrapped DB text and collided
// with the global 40003=totpCodeReused frontend localization — so a role/binding
// validation error rendered as "TOTP code reused". These codes are fresh.
//
// Numbering: 400xx bad-request, 404xx not-found.
var (
	codeInvalidRole        = errcode.Code{HTTP: 400, Num: 40030}
	codeInvalidBinding     = errcode.Code{HTTP: 400, Num: 40031}
	codeRoleNotFound       = errcode.Code{HTTP: 404, Num: 40420}
	codeParentNotInTenant  = errcode.Code{HTTP: 404, Num: 40421}
	codeSubjectNotInTenant = errcode.Code{HTTP: 404, Num: 40422}
	codeAppRoleNotInParent = errcode.Code{HTTP: 404, Num: 40423}
)

func init() {
	errcode.Bind(ErrInvalidRole, codeInvalidRole)
	errcode.Bind(ErrInvalidBinding, codeInvalidBinding)
	errcode.Bind(ErrRoleNotFound, codeRoleNotFound)
	errcode.Bind(ErrParentNotInTenant, codeParentNotInTenant)
	errcode.Bind(ErrSubjectNotInTenant, codeSubjectNotInTenant)
	errcode.Bind(ErrAppRoleNotInParent, codeAppRoleNotInParent)
}
