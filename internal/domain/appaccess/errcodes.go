package appaccess

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the app-access-policy domain. response.MapError renders a
// bound sentinel with its safe message; any unbound error (a wrapped DB
// failure, a "validator not configured" misconfig) becomes a logged 500 that
// never leaks internals. The former handler funnelled every service error
// through 40003 + err.Error(), which both leaked wrapped DB text and collided
// with the global 40003=totpCodeReused frontend localization. These are fresh.
//
// Numbering: 400xx bad-request, 404xx not-found.
var (
	codeInvalidPolicy      = errcode.Code{HTTP: 400, Num: 40040}
	codeParentNotInTenant  = errcode.Code{HTTP: 404, Num: 40430}
	codeSubjectNotInTenant = errcode.Code{HTTP: 404, Num: 40431}
)

func init() {
	errcode.Bind(ErrInvalidPolicy, codeInvalidPolicy)
	errcode.Bind(ErrParentNotInTenant, codeParentNotInTenant)
	errcode.Bind(ErrSubjectNotInTenant, codeSubjectNotInTenant)
}
