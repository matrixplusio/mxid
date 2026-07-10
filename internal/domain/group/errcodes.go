package group

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the group domain, declared next to the sentinels they map.
// response.MapError does the lookup. The rule-validation sentinels all share
// codeBadRule (40010); the wrapped error's own message carries the specific
// field/operator so MapError still returns a useful message.
var (
	codeGroupNotFound   = errcode.Code{HTTP: 404, Num: 40401}
	codeUserNotInTenant = errcode.Code{HTTP: 404, Num: 40402}
	// 40010 (NOT 40003): 40003 is the frontend's global totpCodeReused
	// localization — a bad dynamic-group rule expression rendered as "TOTP code
	// reused". 40010 is non-localized, so the frontend shows the real message.
	codeBadRule         = errcode.Code{HTTP: 400, Num: 40010}
	codeGroupNotDynamic = errcode.Code{HTTP: 400, Num: 40002}
	codeGroupHasMembers = errcode.Code{HTTP: 409, Num: 40901}
	codeGroupIsDynamic  = errcode.Code{HTTP: 409, Num: 40902}
)

func init() {
	// service.go
	errcode.Bind(ErrGroupNotFound, codeGroupNotFound)
	errcode.Bind(ErrUserNotInTenant, codeUserNotInTenant)
	errcode.Bind(ErrGroupHasMembers, codeGroupHasMembers)
	// rule_sync.go
	errcode.Bind(ErrRuleNotFound, codeGroupNotFound) // "group has no rule" — a 404
	errcode.Bind(ErrGroupNotDynamic, codeGroupNotDynamic)
	errcode.Bind(ErrGroupIsDynamic, codeGroupIsDynamic)
	// rule.go (validation)
	errcode.Bind(ErrRuleEmpty, codeBadRule)
	errcode.Bind(ErrRuleUnknownField, codeBadRule)
	errcode.Bind(ErrRuleUnknownCmp, codeBadRule)
	errcode.Bind(ErrRuleInvalidValue, codeBadRule)
	errcode.Bind(ErrRuleNestedNotSupported, codeBadRule)
}
