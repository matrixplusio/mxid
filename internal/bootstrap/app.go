package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/middleware"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/metrics"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/version"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// appendOriginsFromURLs adds the scheme://host[:port] origin of each non-empty
// URL to origins, de-duplicated. Malformed or schemeless/hostless URLs are
// skipped. Used so the CSRF/CORS allow-list automatically trusts the configured
// issuer / portal / console URLs without a duplicate allowed_origins entry.
func appendOriginsFromURLs(origins []string, urls ...string) []string {
	seen := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		seen[o] = struct{}{}
	}
	for _, raw := range urls {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		o := u.Scheme + "://" + u.Host
		if _, ok := seen[o]; !ok {
			seen[o] = struct{}{}
			origins = append(origins, o)
		}
	}
	return origins
}

// App holds all shared dependencies for the application.
type App struct {
	Config    *Config
	Logger    *zap.Logger
	DB        *gorm.DB
	Redis     *redis.Client
	Router    *gin.Engine
	EventBus  *event.Bus
	IDGen     *snowflake.Generator
	MasterKey *crypto.MasterKey

	// Route groups for domain module registration
	ConsoleGroup  *gin.RouterGroup
	PortalGroup   *gin.RouterGroup
	OpenAPIGroup  *gin.RouterGroup
	ProtocolGroup *gin.RouterGroup
}

// NewApp initializes all application dependencies.
func NewApp(configPath string) (*App, error) {
	// Load config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// Init logger
	logger, err := InitLogger(&cfg.Log)
	if err != nil {
		return nil, fmt.Errorf("init logger: %w", err)
	}
	// Wire pkg/response's package logger so InternalError can log the real
	// cause of a 500 (never sent to the client) instead of swallowing it.
	response.SetLogger(logger)

	// Init database
	db, err := InitDatabase(&cfg.Database, logger)
	if err != nil {
		return nil, fmt.Errorf("init database: %w", err)
	}

	// Run migrations
	if err := RunMigrations(&cfg.Database, logger); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	// Init Redis
	rdb, err := InitRedis(&cfg.Redis, logger)
	if err != nil {
		return nil, fmt.Errorf("init redis: %w", err)
	}

	// Init snowflake ID generator
	idGen, err := snowflake.New(cfg.Snowflake.NodeID)
	if err != nil {
		return nil, fmt.Errorf("init snowflake: %w", err)
	}

	// Init event bus
	eventBus := event.NewBus(logger)

	// Load master encryption key (fatal if missing or malformed — commercial-grade requirement)
	masterKey, err := crypto.NewMasterKey(cfg.Crypto.KeyEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("init master key (set MXID_CRYPTO_KEY_ENCRYPTION_KEY to base64(32 random bytes)): %w", err)
	}
	// Wire the process-wide MasterKey used by crypto.Secret's driver.Valuer /
	// sql.Scanner (and Value()/Scan() have no context to thread a key through).
	// MUST happen before any crypto.Secret is persisted or loaded.
	crypto.SetSecretMasterKey(masterKey)

	// Init router
	router := InitRouter(&cfg.Server, logger)

	// Readiness probe pings DB + Redis. Registered here (before the heavy
	// middleware below) so it escapes rate-limit / CSRF, same as /health.
	RegisterReadyz(router, db, rdb)

	// Prometheus scrape endpoint. Registered before the heavy middleware so it
	// is never rate-limited / CSRF-checked and does not count itself. The
	// deployment (nginx) MUST keep /metrics internal-only.
	metrics.SetBuildInfo(version.Version)
	router.GET("/metrics", metrics.Handler())

	// Resolve trusted-origins list. Single source of truth for both CORS
	// and CSRF so the two cannot drift apart.
	origins := cfg.Server.AllowedOrigins
	if len(origins) == 0 {
		origins = middleware.DefaultCORSConfig().AllowOrigins
	}
	// Auto-trust the origins of the configured canonical URLs (issuer / portal
	// / console). Setting the deployment host in one place then clears CORS +
	// CSRF for it, so single-domain deploys don't also have to maintain a
	// parallel allowed_origins entry.
	origins = appendOriginsFromURLs(origins,
		cfg.Server.IssuerURL, cfg.Server.PortalURL, cfg.Server.ConsoleURL)

	// Global per-IP rate-limit cap. Mode-aware on purpose:
	//   - release (prod): a proper edge (nginx host-net / userland-proxy=false /
	//     cloud LB) forwards the real client IP, so KeyByClientIP buckets each
	//     real client. 1200/min is generous for one SPA user yet cuts bulk
	//     automation. Narrow `trusted_proxies` so intranet clients aren't
	//     collapsed (see InitRouter warning).
	//   - debug (dev): on Docker Desktop every request shares the gateway IP
	//     (192.168.65.1) — a per-IP cap can't discriminate users, so keep it
	//     effectively out of the way to avoid false 429s during local testing.
	ipRateLimit := 1200
	if cfg.Server.Mode != "release" {
		ipRateLimit = 30000
	}

	// Apply shared middleware. CSRF is router-level (not per-group) with an
	// explicit skip-list — fail-safe: any new route is protected by default,
	// only the documented cross-origin surfaces (SSO protocol callbacks,
	// bearer-auth APIs, health probes) are opted out.
	router.Use(
		middleware.RequestID(),
		metrics.Middleware(),
		middleware.Logger(logger),
		middleware.SecurityHeaders(cfg.Server.Mode == "release"),
		middleware.CORS(middleware.CORSConfig{AllowOrigins: origins}),
		middleware.CSRF(middleware.CSRFConfig{
			TrustedOrigins: origins,
			SkipPaths: []string{
				"/protocol/", // OIDC/SAML/CAS receive RP POSTs cross-site by design
				"/openapi/",  // bearer-auth API tokens
				// Browser-extension form-fill: pairing has no binding token yet and
				// the extension reaches these without a trusted SPA Origin. pair is
				// step-up gated; the app-list is a read. The credential/descriptor
				// writes (under /apps/:id/) carry the binding token and pass via
				// SkipWithHeader below.
				"/api/v1/portal/formfill/",
				"/healthz",
				"/metrics",
			},
			AllowBearerAuth: true,
			SkipWithHeader:  "X-MXID-FormFill-Token",
		}),
		// Global per-IP cap (mode-aware, see ipRateLimit above). The SSE event
		// stream is exempt: a long-lived, self-reconnecting connection that
		// must not burn the budget.
		middleware.RateLimiter(rdb, middleware.RateLimitRule{
			Name: "ip", Limit: ipRateLimit, Window: time.Minute,
			KeyFunc:   middleware.KeyByClientIP,
			SkipPaths: []string{"/api/v1/portal/events", "/api/v1/console/events"},
		}),
	)

	// Register route groups
	consoleGroup, portalGroup, openapiGroup, protocolGroup := RegisterRouteGroups(router)

	app := &App{
		Config:        cfg,
		Logger:        logger,
		DB:            db,
		Redis:         rdb,
		Router:        router,
		EventBus:      eventBus,
		IDGen:         idGen,
		MasterKey:     masterKey,
		ConsoleGroup:  consoleGroup,
		PortalGroup:   portalGroup,
		OpenAPIGroup:  openapiGroup,
		ProtocolGroup: protocolGroup,
	}

	return app, nil
}

// Run starts the HTTP server with graceful shutdown.
func (a *App) Run() error {
	srv := &http.Server{
		Addr:        fmt.Sprintf(":%d", a.Config.Server.Port),
		Handler:     a.Router,
		ReadTimeout: 15 * time.Second,
		// WriteTimeout MUST stay 0: a non-zero value arms a write deadline at
		// header-read time that is never reset, so it force-closes long-lived SSE
		// responses (/portal/events, /console/events) mid-stream — before the 25s
		// heartbeat can fire — causing EventSource reconnect storms. Slowloris on
		// the request header is still bounded by ReadHeaderTimeout; request bodies
		// by ReadTimeout.
		WriteTimeout:      0,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		a.Logger.Info("server starting",
			zap.Int("port", a.Config.Server.Port),
			zap.String("mode", a.Config.Server.Mode),
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		a.Logger.Info("shutting down server...")
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	// Close resources
	a.cleanup()

	a.Logger.Info("server stopped")
	return nil
}

func (a *App) cleanup() {
	if sqlDB, err := a.DB.DB(); err == nil {
		sqlDB.Close()
	}
	a.Redis.Close()
	_ = a.Logger.Sync()
}
