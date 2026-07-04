package group

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the group domain, declared next to the sentinels they map.
// Numeric values unchanged from the former inline errors.Is chains;
// response.MapError does the lookup. The rule-validation sentinels all share
// 40003 (bad rule expression); the wrapped error's own message carries the
// specific field/operator so MapError still returns a useful message.
var (
	codeGroupNotFound   = errcode.Code{HTTP: 404, Num: 40401}
	codeUserNotInTenant = errcode.Code{HTTP: 404, Num: 40402}
	codeBadRule         = errcode.Code{HTTP: 400, Num: 40003}
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
