package org

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the org domain, declared next to the sentinels they map.
// Numeric values unchanged from the former inline errors.Is chains;
// response.MapError does the lookup. ErrParentOrgNotFound was split out of
// ErrOrgNotFound in the service so the parent-context 404 keeps its own code.
var (
	codeOrgNotFound       = errcode.Code{HTTP: 404, Num: 40401}
	codeUserNotInTenant   = errcode.Code{HTTP: 404, Num: 40402}
	codeParentOrgNotFound = errcode.Code{HTTP: 404, Num: 40404}
	codeRootOrgDelete     = errcode.Code{HTTP: 403, Num: 40301}
)

func init() {
	errcode.Bind(ErrOrgNotFound, codeOrgNotFound)
	errcode.Bind(ErrUserNotInTenant, codeUserNotInTenant)
	errcode.Bind(ErrParentOrgNotFound, codeParentOrgNotFound)
	errcode.Bind(ErrRootOrgDelete, codeRootOrgDelete)
}
