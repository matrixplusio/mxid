package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/imkerbos/mxid/internal/middleware"
	"go.uber.org/zap"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// sqlStringLiteral matches a single-quoted SQL string literal (handling the ”
// escape). GORM hands the Trace callback already-interpolated SQL, so the
// parameterized form is unrecoverable — redacting the string literals is the
// pragmatic point to strip PII (email / phone), password hashes, tokens and
// other secret column values before they reach the logs.
var sqlStringLiteral = regexp.MustCompile(`'(?:[^']|'')*'`)

// redactSQL replaces every string-literal value in an interpolated SQL statement
// with '?', keeping the statement structure and numeric ids intact for
// debugging while removing sensitive column values. Applied to every logged
// statement (dev and prod alike) — the structure is what matters for diagnosis,
// not the literal values.
func redactSQL(sql string) string {
	return sqlStringLiteral.ReplaceAllString(sql, "'?'")
}

// zapGormLogger adapts zap.Logger to GORM's logger interface.
type zapGormLogger struct {
	logger  *zap.Logger
	level   gormlogger.LogLevel
	slowSQL time.Duration
}

// NewGormLogger creates a GORM logger backed by zap.
func NewGormLogger(logger *zap.Logger, level gormlogger.LogLevel) gormlogger.Interface {
	return &zapGormLogger{
		logger:  logger.Named("gorm"),
		level:   level,
		slowSQL: 200 * time.Millisecond,
	}
}

func (l *zapGormLogger) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	return &zapGormLogger{
		logger:  l.logger,
		level:   level,
		slowSQL: l.slowSQL,
	}
}

func (l *zapGormLogger) Info(_ context.Context, msg string, data ...any) {
	if l.level >= gormlogger.Info {
		l.logger.Info(fmt.Sprintf(msg, data...))
	}
}

func (l *zapGormLogger) Warn(_ context.Context, msg string, data ...any) {
	if l.level >= gormlogger.Warn {
		l.logger.Warn(fmt.Sprintf(msg, data...))
	}
}

func (l *zapGormLogger) Error(_ context.Context, msg string, data ...any) {
	if l.level >= gormlogger.Error {
		l.logger.Error(fmt.Sprintf(msg, data...))
	}
}

func (l *zapGormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	if l.level <= gormlogger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()

	fields := []zap.Field{
		zap.Duration("elapsed", elapsed),
		zap.Int64("rows", rows),
		zap.String("sql", redactSQL(sql)),
	}
	// Correlate the query to its request when the caller threaded the
	// request-scoped context through (repo WithContext(ctx)); best-effort.
	if rid := middleware.RequestIDFromContext(ctx); rid != "" {
		fields = append(fields, zap.String("request_id", rid))
	}

	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		// Expected control-flow outcome (optional-setting lookups, existence
		// checks). Not an error — log at debug without a stacktrace so it
		// stops masquerading as a real failure in the logs.
		if l.level >= gormlogger.Info {
			l.logger.Debug("query: record not found", fields...)
		}
	case err != nil && l.level >= gormlogger.Error:
		l.logger.Error("query error", append(fields, zap.Error(err))...)
	case elapsed > l.slowSQL && l.level >= gormlogger.Warn:
		l.logger.Warn("slow query", fields...)
	case l.level >= gormlogger.Info:
		l.logger.Debug("query", fields...)
	}
}
