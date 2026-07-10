package permission

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the permission domain, declared next to the sentinels they
// map. Numeric values are the frozen API contract (unchanged from the former
// handleServiceError switch); response.MapError does the lookup. Note
// ErrSubjectNotInTenant maps to 40403 here vs 40406 in the app domain — they are
// distinct package-local sentinels, bound independently.
var (
	codeRoleNotFound       = errcode.Code{HTTP: 404, Num: 40401}
	codeMemberNotFound     = errcode.Code{HTTP: 404, Num: 40402}
	codeSubjectNotInTenant = errcode.Code{HTTP: 404, Num: 40403}
	codeScopeNotInTenant   = errcode.Code{HTTP: 404, Num: 40404}
	codePermissionNotFound = errcode.Code{HTTP: 400, Num: 40002}
	// 40006 (NOT 40003): 40003 is the frontend's global totpCodeReused
	// localization — an incomplete scope rendered as "TOTP code reused". 40006
	// is non-localized, so the frontend shows the real message.
	codeScopeIncomplete    = errcode.Code{HTTP: 400, Num: 40006}
	codeSystemRoleDelete   = errcode.Code{HTTP: 403, Num: 40301}
	codeSuperAdminUserOnly = errcode.Code{HTTP: 400, Num: 40005}
	codeRoleCodeExists     = errcode.Code{HTTP: 409, Num: 40901}
)

func init() {
	errcode.Bind(ErrRoleNotFound, codeRoleNotFound)
	errcode.Bind(ErrMemberNotFound, codeMemberNotFound)
	errcode.Bind(ErrSubjectNotInTenant, codeSubjectNotInTenant)
	errcode.Bind(ErrScopeNotInTenant, codeScopeNotInTenant)
	errcode.Bind(ErrPermissionNotFound, codePermissionNotFound)
	errcode.Bind(ErrScopeIncomplete, codeScopeIncomplete)
	errcode.Bind(ErrSystemRoleDelete, codeSystemRoleDelete)
	errcode.Bind(ErrSuperAdminUserOnly, codeSuperAdminUserOnly)
	errcode.Bind(ErrRoleCodeExists, codeRoleCodeExists)
}
