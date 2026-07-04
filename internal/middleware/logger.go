package middleware

import (
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// sensitiveQueryParams are query-string keys whose VALUES are bearer credentials
// or one-shot secrets — magic-link / password-reset / email-verify tokens, CAS
// service tickets, OAuth authorization codes / state. They must never land in
// access logs in cleartext. The value-level RedactingCore only matches zap field
// KEYS, so a single "query" field carrying "?token=..." slips straight past it;
// redactQuery closes that gap.
var sensitiveQueryParams = map[string]bool{
	"token": true, "ticket": true, "code": true, "state": true,
	"access_token": true, "refresh_token": true, "id_token": true,
	"client_secret": true, "secret": true, "password": true,
	"authorization": true, "api_key": true, "apikey": true, "assertion": true,
}

// redactQuery returns rawQuery with any sensitive parameter value replaced by
// REDACTED, keeping the rest for debuggability. An unparseable query is redacted
// wholesale (fail-closed).
func redactQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "REDACTED"
	}
	changed := false
	for k := range values {
		if sensitiveQueryParams[strings.ToLower(k)] {
			values[k] = []string{"REDACTED"}
			changed = true
		}
	}
	if !changed {
		return rawQuery
	}
	return values.Encode()
}

// Logger returns a Gin middleware that logs HTTP requests using zap.
func Logger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		fields := []zap.Field{
			zap.Int("statusCode", status),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", redactQuery(query)),
			zap.String("clientIp", c.ClientIP()),
			zap.Int64("costMs", latency.Milliseconds()),
			zap.Int("size", c.Writer.Size()),
		}

		if requestID, exists := c.Get("request_id"); exists {
			fields = append(fields, zap.Any("request_id", requestID))
		}

		if len(c.Errors) > 0 {
			fields = append(fields, zap.String("errors", c.Errors.ByType(gin.ErrorTypePrivate).String()))
		}

		switch {
		case status >= 500:
			logger.Error("server error", fields...)
		case status >= 400:
			logger.Warn("client error", fields...)
		default:
			logger.Info("request", fields...)
		}
	}
}
