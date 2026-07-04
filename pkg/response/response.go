package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// logger is the package-level zap logger used by InternalError to record the
// real cause of a 500 without ever leaking it to the client. Nil until
// SetLogger is called during bootstrap — InternalError degrades gracefully
// (no logging) if it's never wired.
var logger *zap.Logger

// SetLogger wires the process-wide zap logger for this package. Called once
// during bootstrap, right after the logger is constructed. Safe to call with
// nil (equivalent to leaving logging disabled).
func SetLogger(l *zap.Logger) {
	logger = l
}

// Response is the unified API response structure.
type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
	Detail  string `json:"detail,omitempty"`
	// TraceID echoes the per-request id (set by middleware.RequestID) so a
	// client / support can correlate a response to the server log line for it.
	TraceID string `json:"traceId,omitempty"`
}

// traceID returns the request id stamped on the context by middleware.RequestID,
// or "" if absent (e.g. a response built outside the middleware chain).
func traceID(c *gin.Context) string {
	if v, ok := c.Get("request_id"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// PaginatedData wraps paginated results.
type PaginatedData struct {
	Items    any   `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
}

// OK sends a success response.
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{
		Code:    0,
		Message: "ok",
		Data:    data,
		TraceID: traceID(c),
	})
}

// Created sends a 201 response.
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, Response{
		Code:    0,
		Message: "created",
		Data:    data,
		TraceID: traceID(c),
	})
}

// Paginated sends a paginated response.
func Paginated(c *gin.Context, items any, total int64, page, pageSize int) {
	c.JSON(http.StatusOK, Response{
		Code:    0,
		Message: "ok",
		Data: PaginatedData{
			Items:    items,
			Total:    total,
			Page:     page,
			PageSize: pageSize,
		},
		TraceID: traceID(c),
	})
}

// Error sends an error response.
func Error(c *gin.Context, httpStatus int, code int, message, detail string) {
	c.JSON(httpStatus, Response{
		Code:    code,
		Message: message,
		Detail:  detail,
		TraceID: traceID(c),
	})
}

// BadRequest sends a 400 error.
func BadRequest(c *gin.Context, code int, message string) {
	Error(c, http.StatusBadRequest, code, message, "")
}

// Unauthorized sends a 401 error.
func Unauthorized(c *gin.Context, code int, message string) {
	Error(c, http.StatusUnauthorized, code, message, "")
}

// Forbidden sends a 403 error.
func Forbidden(c *gin.Context, code int, message string) {
	Error(c, http.StatusForbidden, code, message, "")
}

// NotFound sends a 404 error.
func NotFound(c *gin.Context, code int, message string) {
	Error(c, http.StatusNotFound, code, message, "")
}

// Conflict sends a 409 error. Use when a uniqueness / state precondition
// fails (duplicate code, etc).
func Conflict(c *gin.Context, code int, message string) {
	Error(c, http.StatusConflict, code, message, "")
}

// NoContent sends a 204 with no body. Used by DELETE handlers.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// InternalError sends a 500 error. Default message is intentionally
// generic — callers MUST NOT pass raw err.Error() (leaks internals); pass a
// user-safe label as message.
//
// The optional cause is the real underlying error. When provided (and a
// logger has been wired via SetLogger), it is logged at ERROR level with
// request context — the HTTP response body is unaffected and never contains
// cause.Error(). This is how a 500 stops being silent: the client still sees
// only the generic message + code 50001, but the server log carries the
// root cause for debugging.
func InternalError(c *gin.Context, message string, cause ...error) {
	if message == "" {
		message = "internal server error"
	}
	if logger != nil && len(cause) > 0 && cause[0] != nil {
		fields := []zap.Field{
			zap.String("message", message),
			zap.Error(cause[0]),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
		}
		if requestID, exists := c.Get("request_id"); exists {
			fields = append(fields, zap.Any("request_id", requestID))
		}
		logger.Error("internal server error", fields...)
	}
	Error(c, http.StatusInternalServerError, 50001, message, "")
}
