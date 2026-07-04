package middleware

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const RequestIDHeader = "X-Request-ID"

// requestIDCtxKey is an unexported type so the context value can't collide with
// keys from other packages.
type requestIDCtxKey struct{}

// RequestIDFromContext returns the request id threaded into ctx by RequestID, or
// "" if absent. Ctx-aware loggers (e.g. the GORM logger) use it to correlate a
// deep log line back to the originating request.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// RequestID injects a unique request ID into each request — onto both the
// gin.Context (for c.Get lookups) and the request's context.Context (so it
// propagates into services, repositories and the GORM logger).
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(RequestIDHeader)
		if id == "" {
			id = uuid.New().String()
		}
		c.Set("request_id", id)
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), requestIDCtxKey{}, id))
		c.Header(RequestIDHeader, id)
		c.Next()
	}
}
