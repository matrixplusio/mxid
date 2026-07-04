// Package ginutil holds small helpers shared across gin handlers in the
// console / portal gateways. Centralising them avoids the 29+ inline
// `strconv.ParseInt(c.Param("id"), 10, 64)` repetitions that drift in
// error code / response shape over time.
package ginutil

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/response"
)

// ParseInt64Param reads a path parameter as int64. On failure it writes a 400
// response (code 40001, message "invalid <name>" — the raw value is NOT echoed
// back) and returns ok=false so the caller can early-return:
//
//	id, ok := ginutil.ParseInt64Param(c, "id")
//	if !ok { return }
//
// This is the single shared implementation; the per-domain parseID clones were
// consolidated onto it.
func ParseInt64Param(c *gin.Context, name string) (int64, bool) {
	id, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid "+name)
		return 0, false
	}
	return id, true
}

// UserIDFromContext reads the authenticated user's id stamped by the
// auth middleware. Mirrors authn.GetUserID but lives here so handlers
// in domain packages don't have to import authn just for the ID.
func UserIDFromContext(c *gin.Context) (int64, bool) {
	v, ok := c.Get("user_id")
	if !ok {
		return 0, false
	}
	id, ok := v.(int64)
	return id, ok
}

// UserIDPtr returns the user id as a *int64, useful for service "CreatedBy"
// columns that are nullable.
func UserIDPtr(c *gin.Context) *int64 {
	id, ok := UserIDFromContext(c)
	if !ok {
		return nil
	}
	return &id
}
