package access

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the access (JIT / PAM) domain, declared next to the
// sentinels they map. response.MapError does the lookup: a bound sentinel
// yields (HTTP, Num) with the error's own — safe, user-facing — message; any
// unbound error is an unexpected failure → 500, logged, never leaked.
//
// Numbering: 400xx bad-request, 403xx forbidden, 404xx not-found. The two 403
// codes (40012 self-approval, 40013 approver-not-eligible) are FROZEN — the
// frontend localizes them by number (LOCALIZED_CODES in shared/ui/toast.tsx),
// so they must not change. The former handler used 40003 for createEligibility
// validation errors, which collided with the global 40003=totpCodeReused
// localization and made every eligibility validation error render as "TOTP
// code reused"; the 400xx codes below are fresh and collision-free.
var (
	codeInvalidEligibility    = errcode.Code{HTTP: 400, Num: 40020}
	codeRequestNotAllowed     = errcode.Code{HTTP: 400, Num: 40021}
	codeRequestNotPending     = errcode.Code{HTTP: 400, Num: 40022}
	codeRequestNotCancellable = errcode.Code{HTTP: 400, Num: 40023}
	codeGrantNotRevocable     = errcode.Code{HTTP: 400, Num: 40024}
	codeSelfApproval          = errcode.Code{HTTP: 403, Num: 40012}
	codeApproverNotEligible   = errcode.Code{HTTP: 403, Num: 40013}
	codeRequestNotFound       = errcode.Code{HTTP: 404, Num: 40410}
	codeEligibilityNotFound   = errcode.Code{HTTP: 404, Num: 40411}
)

func init() {
	errcode.Bind(ErrInvalidEligibility, codeInvalidEligibility)
	errcode.Bind(ErrRequestNotAllowed, codeRequestNotAllowed)
	errcode.Bind(ErrRequestNotPending, codeRequestNotPending)
	errcode.Bind(ErrRequestNotCancellable, codeRequestNotCancellable)
	errcode.Bind(ErrGrantNotRevocable, codeGrantNotRevocable)
	errcode.Bind(ErrSelfApproval, codeSelfApproval)
	errcode.Bind(ErrApproverNotEligible, codeApproverNotEligible)
	errcode.Bind(ErrRequestNotFound, codeRequestNotFound)
	errcode.Bind(ErrEligibilityNotFound, codeEligibilityNotFound)
}
