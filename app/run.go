package app

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/access"
	"github.com/imkerbos/mxid/internal/domain/apitoken"
	"github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/appaccess"
	"github.com/imkerbos/mxid/internal/domain/approle"
	"github.com/imkerbos/mxid/internal/domain/audit"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/domain/consent"
	"github.com/imkerbos/mxid/internal/domain/dashboard"
	"github.com/imkerbos/mxid/internal/domain/group"
	"github.com/imkerbos/mxid/internal/domain/offboarding"
	"github.com/imkerbos/mxid/internal/domain/org"
	"github.com/imkerbos/mxid/internal/domain/permission"
	"github.com/imkerbos/mxid/internal/domain/platformconfig"
	"github.com/imkerbos/mxid/internal/domain/provisioning"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/internal/domain/tenant"
	"github.com/imkerbos/mxid/internal/domain/upload"
	"github.com/imkerbos/mxid/internal/domain/user"
	publicpkg "github.com/imkerbos/mxid/internal/gateway/console/public"
	"github.com/imkerbos/mxid/internal/gateway/console/settings"
	systemgw "github.com/imkerbos/mxid/internal/gateway/console/system"
	"github.com/imkerbos/mxid/internal/gateway/portal"
	"github.com/imkerbos/mxid/internal/middleware"
	"github.com/imkerbos/mxid/internal/outbox"
	"github.com/imkerbos/mxid/internal/protocol/cas"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/internal/protocol/saml"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/dlock"
	"github.com/imkerbos/mxid/pkg/ee/license"
	"github.com/imkerbos/mxid/pkg/ee/registry"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/geoip"
	"github.com/imkerbos/mxid/pkg/mailer"
	"github.com/imkerbos/mxid/pkg/metrics"
	"github.com/imkerbos/mxid/pkg/ratelimit"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/sms"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/imkerbos/mxid/pkg/updatecheck"
	"github.com/imkerbos/mxid/pkg/urlswap"
	"github.com/imkerbos/mxid/pkg/version"
)

// Run starts the MXID server: parse flags, build the app, register modules,
// and serve (blocking). Extracted from package main so the EE distribution
// (github.com/imkerbos/mxid-ee) can wrap it — blank-import its feature packages
// to register EE implementations into pkg/ee/registry, then call Run.
func Run() {
	configPath := flag.String("config", "configs", "path to config directory")
	flag.Parse()

	// Operator subcommand: `verify-export` proves a third-party export bundle
	// OFFLINE — no DB, no HMAC key, no config. It must run BEFORE
	// bootstrap.NewApp so it never depends on a live database (a third party
	// running this against an exported directory + a trusted public key has
	// neither): `mxid-server verify-export -dir=/path/to/export -trust=<b64pub>`.
	if flag.Arg(0) == "verify-export" {
		if err := runVerifyExport(flag.Args()[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	a, err := bootstrap.NewApp(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize application: %v\n", err)
		os.Exit(1)
	}

	// Operator subcommand: `audit-export` builds a third-party-verifiable
	// export bundle (entries + anchors + pubkeys) for one chain range and
	// writes it to --out, then exits — it needs the DB (hence after NewApp)
	// but must NOT start the chainer/anchorer/server (same rationale as
	// verify-audit below): `mxid-server -config=configs audit-export
	// -tenant=7 -class=data -from=1 -to=100 -out=/path/to/export`.
	if flag.Arg(0) == "audit-export" {
		if err := runAuditExport(a, flag.Args()[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// Operator subcommand: `verify-audit` walks every audit chain head and
	// recomputes its HMAC chain from genesis, printing per-chain status, then
	// exits — it must NOT build the portal group, register modules, start the
	// chainer goroutine, or serve traffic (that would be a second writer on
	// the same chain). Flags must precede the subcommand (Go's flag package
	// stops parsing at the first non-flag arg): `mxid-server -config=configs
	// verify-audit`.
	if flag.Arg(0) == "verify-audit" {
		if err := runVerifyAudit(a); err != nil {
			fmt.Fprintf(os.Stderr, "verify-audit failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Install the audit capture plugin: every write to an Audited model now
	// emits a before/after event into the tamper-proof chain, inside the
	// caller's transaction (a capture failure aborts the write). Wired here in
	// package app — not in bootstrap — because internal/domain/audit imports
	// internal/bootstrap (register.go), so bootstrap cannot import audit.
	// Placed after the verify-audit early-return: the read-only verifier needs
	// no capture. Placed before registerModules so all runtime writes are
	// captured.
	if err := a.DB.Use(audit.NewCapturePlugin(audit.NewCapturer(a.IDGen))); err != nil {
		a.Logger.Fatal("install audit capture plugin", zap.Error(err))
	}

	// Public portal group MUST be created before registerModules so the
	// password-reset / magic-link / sms-otp routes wired inside it have a
	// non-nil group to mount on.
	publicPortalGroup = a.Router.Group("/api/v1/portal-public")

	// workerCtx is cancelled on SIGINT/SIGTERM so the background workers
	// (outbox, audit chainer, audit anchorer, retention purge) drain and stop
	// on shutdown instead of being killed mid-tick. a.Run() independently
	// handles the same signal for graceful HTTP shutdown; both react to it.
	workerCtx, workerStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer workerStop()

	registerModules(a, workerCtx)

	// Public metadata endpoint — both portal and console SPAs fetch this
	// before login to learn the canonical issuer / portal / console URLs.
	// registry.RegisteredFeatures() is empty in CE and lists the EE feature keys
	// blank-imported into this binary (e.g. external_idp) in EE — so /system/info
	// only advertises code-separated features actually present here.
	bootstrap.RegisterSystemInfo(a.Router, &a.Config.Server, version.Version, registry.RegisteredFeatures())
	publicpkg.Register(a.Router, settingService, a.Config.Tenant.DefaultID)

	// File upload (app icons) + serve, both DB-backed (internal/domain/upload) so
	// the backend holds no local file state: k8s needs no PVC/RWO volume, docker
	// survives container restarts, and every replica serves identical bytes.
	if err := bootstrap.RegisterUpload(a.Router, a.ConsoleGroup, a.IDGen, upload.NewRepository(a.DB)); err != nil {
		a.Logger.Fatal("register upload", zap.Error(err))
	}

	if err := a.Run(); err != nil {
		a.Logger.Fatal("application error", zap.Error(err))
	}
}

// settingService + mailerSvc are wired in registerModules and held here so
// the portal email-verify handler (which lives in main.go via bootstrap)
// can reuse the same instance instead of constructing a second mailer.
var (
	settingService    *setting.Service
	mailerSvc         *mailer.Mailer
	publicPortalGroup *gin.RouterGroup
)

func registerModules(a *bootstrap.App, workerCtx context.Context) {
	// 0a. Catch-all audit middleware. Installed on the console + portal GROUPS
	// at the very top of registerModules — before any route is registered on
	// them — so it sits in their handler chain. (Router-level .Use here would
	// NOT work: the groups were created in NewApp and already snapshotted the
	// engine's middleware slice, so a later engine.Use doesn't reach them.)
	// The recorder resolves lazily — the audit service is constructed further
	// down — so this closure is a no-op during the bootstrap window and the
	// real recorder from then on. Runs after AuthMiddleware (added later in the
	// same group chain) so the actor is already stamped into the request ctx.
	var auditRecorder func(*gin.Context)
	auditCatchAll := func(c *gin.Context) {
		c.Next()
		if auditRecorder != nil {
			auditRecorder(c)
		}
	}
	a.ConsoleGroup.Use(auditCatchAll)
	a.PortalGroup.Use(auditCatchAll)

	// 0. Settings module — runtime tunable config (SMTP, password policy,
	// branding, etc). Initialized first so other modules can read defaults.
	settingRepo := setting.NewRepositoryWithIDGen(a.DB, a.IDGen)
	settingService = setting.NewService(settingRepo, a.MasterKey)
	settingService.SetEventBus(a.EventBus)
	settingService.SetRedisInvalidation(workerCtx, a.Redis)
	mailerSvc = mailer.New(settingService)

	// Platform-level config (license + install fingerprint) lives in a dedicated
	// NON-tenant-scoped table so it can be read at boot / pre-login without a
	// tenant scope (the fail-closed tenantscope plugin would otherwise reject
	// these scope-less boot reads). See internal/domain/platformconfig.
	platformConfigService := platformconfig.NewService(platformconfig.NewRepository(a.DB))

	// Installation fingerprint — for install-bound licenses. Derived from a
	// per-install UUID (generated once, stored as platform config) + the
	// PostgreSQL cluster's system_identifier. A license bound to a fingerprint
	// only verifies on that installation; unbound licenses stay portable.
	installUUID := ensureInstallUUID(platformConfigService, a.Logger)
	if installUUID != "" {
		var sysID uint64
		if err := a.DB.Raw("SELECT system_identifier FROM pg_control_system()").Scan(&sysID).Error; err != nil {
			a.Logger.Warn("read postgres system_identifier failed; install-bound licenses won't verify", zap.Error(err))
		} else {
			license.SetInstallFingerprint(license.Fingerprint(installUUID, sysID))
		}
	}

	// Edition: verify the signed license stored in the DB (the License setting,
	// pasted in the console) and install the active Manager. DB-only and
	// persistent — surviving image swaps; the console hot-reloads it on save.
	// No token → CE; expired → CE limits with existing data grandfathered. The
	// signature is checked against the embedded vendor public key, so the old
	// admin-editable enable_enterprise boolean can no longer unlock EE.
	licMgr := reloadLicense(context.Background(), platformConfigService)
	if err := licMgr.LoadErr(); err != nil {
		a.Logger.Warn("license invalid — running as Community Edition", zap.Error(err))
	}
	a.Logger.Info("edition resolved",
		zap.String("edition", string(licMgr.Edition())),
		zap.String("customer", licMgr.Customer()),
		zap.Int("features", len(licMgr.EnabledFeatures())))

	// A local reloadLicense only fixes the pod that served the console's
	// putLicense request — every other replica keeps enforcing the OLD
	// edition until restart. Subscribe every pod (including this one) so a
	// license change broadcast over Redis converges the whole fleet; mirrors
	// the Casbin resync subscriber's design (wireCasbinSync).
	startLicenseReloadSubscriber(workerCtx, a.Redis, platformConfigService, a.Logger)

	// Build the handler now; its ROUTES are mounted later (after AuthMiddleware
	// + authz are on the console group) so settings endpoints aren't reachable
	// unauthenticated. The service above is constructed early because other
	// modules read config defaults from it during bootstrap.
	settingsHandler := settings.NewHandler(settingService, platformConfigService, mailerSvc, a.Config.Tenant.DefaultID, a.Redis)

	// 1. Session manager
	sessionMgr := session.NewManager(
		a.Redis,
		a.Config.Session.IdleTimeout,
		a.Config.Session.AbsoluteTimeout,
	)
	// Runtime session policy — admin can change idle / absolute via settings
	// UI. Default tenant scope (auth runs pre-tenant-resolve). Zero values
	// in DB fall back to the YAML-driven static config.
	sessionMgr.SetPolicyProvider(func(ctx context.Context) (time.Duration, time.Duration) {
		pol, err := settingService.SecurityPolicy(ctx, a.Config.Tenant.DefaultID)
		if err != nil {
			return 0, 0
		}
		return time.Duration(pol.Session.IdleMinutes) * time.Minute,
			time.Duration(pol.Session.AbsoluteHours) * time.Hour
	})

	// 2. User module (needed by authn adapter and protocol resolvers)
	userModule := user.Register(a)

	// 3. Authentication module — bridge user repo via adapters
	authQuerier := authn.BuildAuthQuerier(func(ctx context.Context, tenantID int64, username string) (*authn.UserAuth, error) {
		u, err := userModule.Repo.GetByUsername(ctx, tenantID, username)
		if err != nil {
			return nil, err
		}
		displayName := ""
		if u.DisplayName != nil {
			displayName = *u.DisplayName
		}
		return &authn.UserAuth{
			ID:                u.ID,
			Username:          u.Username,
			DisplayName:       displayName,
			PasswordHash:      u.PasswordHash,
			Status:            int(u.Status),
			PasswordChangedAt: u.PasswordChangedAt,
		}, nil
	})

	userQuerier := authn.BuildUserQuerier(
		func(ctx context.Context, id int64) (*authn.UserInfo, error) {
			u, err := userModule.Repo.GetByID(ctx, id)
			if err != nil {
				return nil, err
			}
			displayName := ""
			if u.DisplayName != nil {
				displayName = *u.DisplayName
			}
			avatar := ""
			if u.Avatar != nil {
				avatar = *u.Avatar
			}
			return &authn.UserInfo{
				ID:          u.ID,
				Username:    u.Username,
				DisplayName: displayName,
				Avatar:      avatar,
				Status:      int(u.Status),
			}, nil
		},
		func(ctx context.Context, id int64, ip string) error {
			return userModule.Repo.UpdateLastLogin(ctx, id, ip)
		},
		func(ctx context.Context, id int64, status int) error {
			return userModule.Repo.UpdateStatus(ctx, id, status)
		},
	)

	mfaVerifier := newUserMFAVerifierAdapter(userModule)
	authnModule := authn.Register(a, sessionMgr, authQuerier, userQuerier, mfaVerifier)
	authnModule.Engine.SetLoginRecorder(newUserLoginRecorderAdapter(userModule, a.Logger))

	// SECURITY: revoke every session for a user whose password was reset (admin
	// reset or forgot-password recovery — both flagged admin_reset). Otherwise a
	// stolen live session survives the canonical compromise-recovery action. The
	// self-service change path revokes-except-current itself and is NOT flagged
	// admin_reset, so it is intentionally skipped here.
	a.EventBus.Subscribe(event.UserPasswordChanged, func(ctx context.Context, ev event.Event) {
		p, ok := ev.Payload.(map[string]any)
		if !ok {
			return
		}
		if adminReset, _ := p["admin_reset"].(bool); !adminReset {
			return
		}
		uid, _ := p["user_id"].(int64)
		if uid == 0 {
			return
		}
		_ = sessionMgr.DeleteAllByUser(ctx, session.NamespacePortal, uid)
		_ = sessionMgr.DeleteAllByUser(ctx, session.NamespaceConsole, uid)
	})

	// A deleted user is soft-deleted, so a fresh login is blocked by GORM's
	// soft-delete scope on GetByUsername — but any session they already hold
	// keeps resolving roles/apps until it expires (the access-resolution queries
	// do not re-check deleted_at). Revoke every session on delete so access is
	// cut immediately, not at session TTL.
	a.EventBus.Subscribe(event.UserDeleted, func(ctx context.Context, ev event.Event) {
		p, ok := ev.Payload.(map[string]any)
		if !ok {
			return
		}
		uid, _ := p["user_id"].(int64)
		if uid == 0 {
			return
		}
		_ = sessionMgr.DeleteAllByUser(ctx, session.NamespacePortal, uid)
		_ = sessionMgr.DeleteAllByUser(ctx, session.NamespaceConsole, uid)

		// Strip the deleted user's derived rows so they vanish from every
		// group/org/role member listing and hold no residual access. These join
		// tables carry ON DELETE CASCADE on user_id, but a soft delete never
		// fires it — remove them explicitly. Raw Exec is garble-safe (no struct
		// scan) and bypasses the tenantscope plugin (no fail-closed on a
		// detached event context).
		bg := context.Background()
		for _, stmt := range []struct {
			sql  string
			what string
		}{
			{"DELETE FROM mxid_user_group_member WHERE user_id = ?", "group memberships"},
			{"DELETE FROM mxid_user_org WHERE user_id = ?", "org memberships"},
			{"DELETE FROM mxid_role_binding WHERE subject_type = 'user' AND subject_id = ?", "role bindings"},
		} {
			if err := a.DB.WithContext(bg).Exec(stmt.sql, uid).Error; err != nil && a.Logger != nil {
				a.Logger.Warn("cleanup deleted user's derived rows failed",
					zap.String("what", stmt.what), zap.Int64("user_id", uid), zap.Error(err))
			}
		}
	})

	// Brute-force limiter for the password login path (per-IP + per-user).
	// Replaces the old permanent mxid_user.status auto-lock with an
	// auto-expiring Redis lock; admin LockUser stays the only permanent lock.
	// Window/lockout mirror the YAML login defaults; MaxAttempts uses the
	// configured threshold (fallback 5). Fail-closed: a Redis outage on this
	// high-value path conservatively blocks rather than admitting unlimited
	// guesses.
	loginMaxAttempts := a.Config.Security.Login.MaxFailedAttempts
	if loginMaxAttempts <= 0 {
		loginMaxAttempts = 5
	}
	loginLockout := a.Config.Security.Login.LockoutDuration
	if loginLockout <= 0 {
		loginLockout = 15 * time.Minute
	}
	if loginLimiter, err := ratelimit.New(a.Redis, ratelimit.Config{
		Purpose:     "login",
		MaxAttempts: loginMaxAttempts,
		Window:      loginLockout,
		Lockout:     loginLockout,
	}); err != nil {
		a.Logger.Error("login rate limiter init failed: " + err.Error())
	} else {
		authnModule.Engine.SetLoginLimiter(loginLimiter)
	}

	// Live security policy — read setting DB on every check (cached by
	// setting.Service itself) so admins can tighten without a restart.
	// YAML LoginConfig remains the fallback when DB rows are absent.
	userModule.Service.SetPasswordPolicyProvider(func(ctx context.Context, tenantID int64) user.PasswordPolicy {
		// Pin the provider's tenant so the scoped SecurityPolicy read succeeds in
		// scope-less phases too (registration / password reset run pre-login).
		// The provider's contract is "policy for tenantID" (may be 0 = global),
		// so scoping to it is correct in every caller — same fix as Login/Captcha.
		ctx = tenantscope.WithTenant(ctx, tenantID)
		pol, err := settingService.SecurityPolicy(ctx, tenantID)
		if err != nil {
			pol = setting.DefaultSecurityPolicy()
		}
		return user.PasswordPolicy{
			MinLength:        pol.Password.MinLength,
			RequireUppercase: pol.Password.RequireUppercase,
			RequireLowercase: pol.Password.RequireLowercase,
			RequireNumber:    pol.Password.RequireNumber,
			RequireSpecial:   pol.Password.RequireSpecial,
			HistoryCount:     pol.Password.HistoryCount,
		}
	})
	authnModule.Engine.SetLoginPolicyProvider(func(ctx context.Context, tenantID int64) (int, time.Duration) {
		// Login runs before any tenant scope is in context (see engine.go). Pin
		// the provider's tenant so the scoped SecurityPolicy read succeeds rather
		// than failing closed and silently falling back to defaults — otherwise
		// the admin-configured lockout policy never takes effect.
		ctx = tenantscope.WithTenant(ctx, tenantID)
		pol, err := settingService.SecurityPolicy(ctx, tenantID)
		if err != nil {
			pol = setting.DefaultSecurityPolicy()
		}
		return pol.Login.MaxFailedAttempts, time.Duration(pol.Login.LockoutMinutes) * time.Minute
	})
	// CaptchaAfterFailures: captcha is demanded only once the client IP has
	// crossed this many login failures. Returning 0 keeps captcha mandatory
	// on every attempt (the stricter pre-existing behaviour).
	authnModule.Handler.SetCaptchaThresholdProvider(func(ctx context.Context, tenantID int64) int {
		// Same pre-login scope fix as LoginPolicy above. Without pinning the
		// tenant the scoped read fails closed, this returns 0, and captcha is
		// forced on EVERY login regardless of the admin's CaptchaAfterFailures
		// setting. The 0 fallback stays as a fail-safe for genuine DB errors.
		ctx = tenantscope.WithTenant(ctx, tenantID)
		pol, err := settingService.SecurityPolicy(ctx, tenantID)
		if err != nil {
			return 0
		}
		return pol.Login.CaptchaAfterFailures
	})
	// License quota — block user creation when MaxUsers is set and the
	// global user count already meets the cap. Zero MaxUsers = unlimited
	// (OSS / no license).
	userModule.Service.SetLicenseQuotaCheck(func(ctx context.Context, tenantID int64) error {
		// Cap from the verified license edition: CE (and expired EE) → CEMaxUsers
		// (100); active EE → its MaxUsers (0 = unlimited). Existing users over the
		// cap are grandfathered — we only block creating NEW ones past it.
		cap := license.Current().UserCap()
		if cap <= 0 {
			return nil // unlimited
		}
		// Count is platform-wide (not scoped to the creating tenant); run under a
		// cross-tenant escape so the isolation plugin doesn't narrow it.
		ctx = tenantscope.WithCrossTenant(ctx)
		n, err := userModule.Repo.CountAll(ctx)
		if err != nil {
			return nil
		}
		if n >= int64(cap) {
			return user.ErrLicenseQuotaExceeded
		}
		return nil
	})

	// Welcome email — soft-fail subscriber on user.created. Logs on send
	// failures (missing SMTP, missing email, template error) but never
	// blocks creation; mail is a courtesy, not a flow requirement.
	a.EventBus.Subscribe(event.UserCreated, func(ctx context.Context, evt event.Event) {
		p, ok := evt.Payload.(map[string]any)
		if !ok {
			return
		}
		email, _ := p["email"].(string)
		if email == "" {
			return
		}
		tid, _ := p["tenant_id"].(int64)
		username, _ := p["username"].(string)
		displayName, _ := p["display_name"].(string)
		if displayName == "" {
			displayName = username
		}
		if err := mailerSvc.SendWelcomeEmail(ctx, tid, email, displayName, username, a.Config.Server.PortalURL); err != nil {
			a.Logger.Warn("welcome email send failed",
				zap.String("username", username),
				zap.String("email", email),
				zap.Error(err))
		}
	})

	// Remember-me cookie TTL — admin can change via security/session policy.
	authnModule.Handler.SetRememberMeProvider(func(ctx context.Context) int {
		pol, err := settingService.SecurityPolicy(ctx, a.Config.Tenant.DefaultID)
		if err != nil {
			return 0
		}
		return pol.Session.RememberMeHours * 3600
	})

	// Login-method gate: reject auth_type when admin disabled it in
	// settings. Default tenant scoping because auth runs pre-tenant-
	// resolution; cross-tenant gating could come later.
	authnModule.Handler.SetLoginMethodGate(func(ctx context.Context, authType string) error {
		m, err := settingService.LoginMethods(ctx, a.Config.Tenant.DefaultID)
		if err != nil {
			return nil
		}
		switch authType {
		case "local", "password", "":
			if !m.Password {
				return fmt.Errorf("密码登录已被管理员关闭")
			}
		case "sms":
			if !m.SMSOTP {
				return fmt.Errorf("短信登录已被管理员关闭")
			}
		case "magic_link":
			if !m.EmailMagicLink {
				return fmt.Errorf("邮件链接登录已被管理员关闭")
			}
		}
		return nil
	})

	// 4. Apply auth middleware to protected route groups
	a.ConsoleGroup.Use(authn.AuthMiddleware(authnModule.SessionMgr, session.NamespaceConsole))
	a.PortalGroup.Use(authn.AuthMiddleware(authnModule.SessionMgr, session.NamespacePortal))

	// 4a-rl. Per-authenticated-user rate limit, layered on top of the global
	// per-IP cap (registered earlier in registerModules/bootstrap). Admin
	// configurable at runtime via SecurityPolicy.RateLimit (0 = unlimited).
	// Must be registered AFTER AuthMiddleware above so authn.CtxUserID is set
	// in the gin context by the time KeyByUserID reads it — gin only applies
	// .Use to routes registered after the call, but middleware ORDER within a
	// request still runs top-to-bottom, so this must come after auth too.
	perUserRL := middleware.RateLimiter(a.Redis, middleware.RateLimitRule{
		Name:    "user",
		Window:  time.Minute,
		KeyFunc: middleware.KeyByUserID(authn.CtxUserID),
		// Exempt the long-lived, self-reconnecting SSE event streams, matching
		// the sibling global per-IP limiter (internal/bootstrap/app.go): a
		// reconnect storm must not burn a legitimate user's per-user budget.
		SkipPaths: []string{"/api/v1/portal/events", "/api/v1/console/events"},
		LimitFunc: func(c *gin.Context) int {
			pol, err := settingService.SecurityPolicy(c.Request.Context(), a.Config.Tenant.DefaultID)
			if err != nil {
				return 0 // fail-open: never break the app on a settings read; the IP cap backstops
			}
			return pol.RateLimit.PerUserPerMinute
		},
	})
	a.ConsoleGroup.Use(perUserRL)
	a.PortalGroup.Use(perUserRL)

	// 4a. Mandatory-MFA-enrollment gate — a session flagged at login (policy
	// requires MFA but the user has none) is blocked from everything except the
	// MFA enrollment surface until they bind a factor. Runs right after auth so
	// it gates before any business handler. Self-heals once a factor exists.
	enrollGate := func(ns string) gin.HandlerFunc {
		return authn.EnrollGateMiddleware(authn.EnrollGateDeps{
			Namespace:  ns,
			SessionMgr: authnModule.SessionMgr,
			HasMFA:     authnModule.Engine.HasMFA,
		})
	}
	a.ConsoleGroup.Use(enrollGate(session.NamespaceConsole))
	a.PortalGroup.Use(enrollGate(session.NamespacePortal))

	// 4b. Install authz middleware lazily — domain modules below need to be
	// constructed first to build the binding provider, but they also need
	// the middleware to be in place when they register their routes. The
	// lazy provider closes over `authzSvc` so it resolves nil during this
	// short bootstrap window and the real service from then on.
	var authzSvc *authz.Service
	authz.InstallLazy(a.ConsoleGroup, func() *authz.Service { return authzSvc })

	// 4c. Now that auth + authz middleware are on the console group, mount
	// the deferred user routes. (user.Register was called above to build
	// the module so other constructors could depend on the user service.)
	// TenantContext sits between authz and routes so super_admin can scope
	// requests to a target tenant via X-Tenant-ID header (used by the
	// console tenant switcher).
	a.ConsoleGroup.Use(middleware.TenantContext())

	// 4d. Step-up MFA on high-risk console operations (deletes + security-
	// critical writes). Deps resolve lazily at request time: authzSvc is
	// assigned later in this bootstrap but always before the first request.
	// No dedicated Audit hook — every high-risk operation already emits its
	// own domain audit event downstream, so the action is on the trail
	// regardless of whether step-up was enforced or skipped (MFA off).
	//
	// stepUpDeps is also reused (unchanged) to build a StepUpChecker for the
	// JIT access-approval handler below (§7), so both mechanisms resolve the
	// session and the step-up window identically — the JIT path just forces
	// the check unconditionally instead of gating on the policy mode.
	stepUpDeps := authn.StepUpDeps{
		SessionMgr: sessionMgr,
		Policy: func(ctx context.Context, tenantID int64) (string, time.Duration) {
			p, err := settingService.MFAPolicy(ctx, tenantID)
			if err != nil {
				p = setting.DefaultMFAPolicy()
			}
			return p.Mode, time.Duration(p.StepUpWindowSeconds) * time.Second
		},
		IsAdmin: func(ctx context.Context, tenantID, userID int64) bool {
			if authzSvc == nil {
				return false
			}
			perms, err := authzSvc.PermissionsForUser(ctx, tenantID, userID)
			return err == nil && len(perms) > 0
		},
		HasMFA: func(ctx context.Context, userID int64) (bool, error) {
			return authnModule.Engine.HasMFA(ctx, userID)
		},
	}
	a.ConsoleGroup.Use(authn.StepUpMiddleware(stepUpDeps))

	// 4e. Deny-by-default authz gateway (HARD MODE). Mounted AFTER AuthMiddleware
	// + authz install (so c has user/tenant + the Service) and BEFORE the module
	// routes, so it sits on every console request post-routing. A matched console
	// route that is neither Protect'd nor AllowPublic'd is 403'd — root-cause
	// guard against shipping an open admin endpoint (a route that simply forgot
	// its authz.Require). The registry is populated by registerConsoleAuthz(a)
	// AFTER all routes mount (hard mode needs mount-time Protect, since the
	// gateway runs before each route's own Require self-registers). That call
	// also audits coverage and loudly logs any governed route missing an authz
	// declaration. Self-service surfaces (profile / security) are AllowPublic'd
	// there.
	a.ConsoleGroup.Use(authz.Gateway(authz.GatewayConfig{
		Logger:    a.Logger,
		AuditOnly: false,
	}))

	userModule.RegisterRoutes(a)

	// Admin per-user session ops (/users/:id/sessions) — mounted HERE, after the
	// console auth/authz/tenant chain, not from inside authn.Register (which runs
	// before .Use). Previously these were unauthenticated due to that ordering.
	authnModule.AdminSession.RegisterRoutes(a.ConsoleGroup)

	// Settings routes mounted here — AFTER AuthMiddleware + authz + tenant
	// context are on the console group — so config read/write requires an
	// authenticated admin session (previously these registered pre-auth and
	// were reachable unauthenticated).
	settingsHandler.Register(a.ConsoleGroup)

	// System update-check (read-only "is there a newer release"). super_admin
	// only via the system.read permission. Outbound GitHub call goes through
	// safehttp; results cached in Redis.
	systemgw.NewHandler(updatecheck.New(a.Redis)).Register(a.ConsoleGroup)

	// EE console routes — registered by the EE distribution's feature packages
	// (github.com/imkerbos/mxid-ee) via pkg/ee/registry. Empty in CE: the EE
	// code isn't compiled in, so these routes simply don't exist.
	for _, mount := range registry.ConsoleMounters() {
		mount(a.ConsoleGroup)
	}

	// 5. Register domain modules
	orgModule := org.Register(a)
	groupModule := group.Register(a)
	permissionModule := permission.Register(a)
	tenantModule := tenant.Register(a)
	// Tenant license quota. CE / expired EE can't reach here anyway (the
	// multi_tenant feature gate blocks tenant create), so this caps EE: its
	// MaxTenants (0 = unlimited). Existing tenants over a cap are grandfathered.
	tenantModule.Service.SetLicenseQuotaCheck(func(ctx context.Context) error {
		cap := license.Current().TenantCap()
		if cap <= 0 {
			return nil // unlimited
		}
		ts, err := tenantModule.Repo.List(ctx)
		if err != nil {
			return nil
		}
		if len(ts) >= cap {
			return tenant.ErrLicenseQuotaExceeded
		}
		return nil
	})
	// Portal login can resolve `tenant` field on the request to a tenant_id
	// via the tenant service. Hooked up here so authn's NewHandler stays
	// decoupled from the tenant domain package.
	authnModule.Handler.SetTenantResolver(func(ctx context.Context, code string) int64 {
		t, err := tenantModule.Service.GetByCode(ctx, code)
		if err != nil || t == nil {
			return 0
		}
		return t.ID
	})
	appModule := app.Register(a)
	// Protocol defaults — admin can set per-protocol TTL + subject strategy
	// via settings UI; applied at Create time when the request leaves the
	// corresponding field blank. Zero values fall through to per-protocol
	// Defaults() funcs at read time.
	appModule.Service.SetProtocolDefaultsProvider(func(ctx context.Context, tenantID int64) app.ProtocolDefaults {
		pd, err := settingService.ProtocolDefaults(ctx, tenantID)
		if err != nil {
			return app.ProtocolDefaults{}
		}
		return app.ProtocolDefaults{
			OIDCAccessTokenTTL:  pd.OIDCAccessTokenTTLSeconds,
			OIDCRefreshTokenTTL: pd.OIDCRefreshTokenTTLSeconds,
			OIDCIDTokenTTL:      pd.OIDCIDTokenTTLSeconds,
			SAMLAssertionTTL:    pd.SAMLAssertionTTLSeconds,
			CASTicketTTL:        pd.CASTicketTTLSeconds,
			DefaultSubject:      pd.DefaultSubjectStrategy,
		}
	})
	auditModule := audit.Register(a)
	// Activate the catch-all recorder installed at the top of registerModules.
	auditRecorder = auditModule.Service.RecordAPIRequest
	// Denormalize ActorName for events that publish only a user_id (app.launched
	// fires from the portal middleware context, which carries no username).
	// Best-effort: a lookup miss leaves ActorName blank but keeps actor_id.
	auditModule.Service.SetUserNameResolver(func(ctx context.Context, userID int64) string {
		u, err := userModule.Repo.GetByID(ctx, userID)
		if err != nil || u == nil {
			return ""
		}
		return u.Username
	})
	// GeoIP enrichment for audit IP. Operator points config geoip.database_path
	// at a MaxMind GeoLite2-City .mmdb; missing / unreadable falls back to
	// noop so a missing licence doesn't break audit. Shared with conditional
	// access (geo-based risk signals) below.
	var geoResolver geoip.Resolver = geoip.NoopResolver{}
	if path := a.Config.GeoIP.DatabasePath; path != "" {
		if geo, err := geoip.NewMaxMindResolver(path); err == nil {
			geoResolver = geoip.PrivateAwareResolver{Inner: geo}
			auditModule.Service.SetGeoResolver(geoResolver)
			a.Logger.Info("geoip resolver loaded", zap.String("path", path))
		} else {
			a.Logger.Warn("geoip mmdb unavailable, audit geo columns will be empty",
				zap.String("path", path), zap.Error(err))
		}
	}

	// Conditional access (adaptive auth): assess login risk + recognise devices.
	// Disabled by default (policy.Enabled=false) so this is inert until an admin
	// turns it on; device history still accumulates so the new-device signal is
	// meaningful once enabled.
	authnModule.Handler.SetConditionalAccess(buildConditionalAccess(a, settingService, geoResolver))
	// Retention cron — purges audit_log rows older than AuditPolicy.RetentionDays
	// every 6h. Hourly would be wasteful (no SLA on prompt deletion); daily
	// risks losing the window during long maintenance. Default-tenant scope
	// because retention is a global compliance knob.
	// Leader-elected: a global cross-tenant purge must run on ONE replica, not
	// every pod (redundant large DELETEs + lock contention).
	go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyAuditRetention, a.Logger, func(ctx context.Context) {
		runAuditRetention(ctx, a, settingService, auditModule.Repo)
	})

	// Dynamic-group reconcile sweeper — a safety net for the event-driven
	// membership sync. Rules normally recompute on org/user events, but a lost
	// or crash-dropped event would otherwise leave a group stale indefinitely
	// (there is no other reconciliation). A periodic full resync bounds that
	// staleness; it also heals anything that drifted while the server was down.
	// Leader-elected: the reconcile rewrites membership, so two pods racing the
	// same recompute would fight over the rows.
	go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyDynamicGroupReconcile, a.Logger, func(ctx context.Context) {
		runDynamicGroupReconcile(ctx, groupModule.Service, a.Config.Tenant.DefaultID)
	})

	// Housekeeping purge sweeper — GC for tables that only grow: expired/revoked
	// API tokens and old login history. Neither carries live security state, so
	// this only bounds table size. Leader-elected: global cross-tenant DELETEs
	// belong on one pod.
	go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyAPITokenPurge, a.Logger, func(ctx context.Context) {
		runHousekeepingPurge(ctx, a, apitoken.NewRepository(a.DB), user.NewGormRepository(a.DB))
	})

	// Transactional outbox worker — durable at-least-once delivery for side
	// effects that must survive a crash (offboarding webhooks, later L2 SCIM
	// pushes). Producers enqueue onto outboxRepo; the worker dispatches by
	// kind. The offboarding webhook handler is registered here; offboarding
	// (wired below) gets outboxRepo to enqueue.
	outboxRepo := outbox.NewRepository(a.DB, a.IDGen)
	outboxWorker := outbox.NewWorker(outboxRepo, a.Logger)
	outboxWorker.Register(offboarding.WebhookKind, newOffboardingWebhookHandler(settingService))
	// Worker is STARTED after RunInit (below) so EE features (e.g. the SCIM
	// deprovision handler) can register their kinds first — Register must not
	// race Run.

	// Per-app outbound provisioning config (L2). Schema + CRUD are CE; the SCIM
	// connector that consumes it is EE, handed the decrypted read via the seam.
	provisioningModule := provisioning.Register(a)

	// Console dashboard aggregation. Live-session gauge sums the interactive
	// (console + portal) namespaces; the protocol SSO session is internal and
	// not a "logged-in user" in the dashboard sense.
	dashboardModule := dashboard.Register(a)
	dashboardModule.Service.SetSessionCounter(func(ctx context.Context) int64 {
		var total int64
		for _, ns := range []string{session.NamespaceConsole, session.NamespacePortal} {
			if n, err := sessionMgr.CountActive(ctx, ns); err == nil {
				total += n
			}
		}
		return total
	})

	consentModule := consent.Register(a)

	// Cross-domain: effective roles for a user resolve THREE binding paths
	// — direct user, group-inherited, and org-inherited (incl. ancestors).
	// Adapters keep permission/ decoupled from group/ and org/.
	permission.RegisterEffectiveRolesRoute(
		a,
		permissionModule.Service,
		newPermissionGroupLookupAdapter(groupModule),
		newPermissionOrgLookupAdapter(orgModule),
		a.Config.Tenant.DefaultID,
	)

	// Now that all module pieces exist, build and publish the authz service
	// for the lazy installer above. The binding provider is wrapped by the
	// two-level cache so per-request Check() pays L1 (sync.Map) at best,
	// L2 (Redis) on cold pods, and the underlying DB join only on a true
	// miss. Cache invalidation is driven by event-bus subscriptions on
	// permission / role mutations (see wireAuthzCacheInvalidation below);
	// callers don't need to remember to call Invalidate manually.
	authzBindings := authz.NewCachedBindingProvider(
		context.Background(),
		newAuthzBindingProvider(a, permissionModule, groupModule, orgModule),
		a.Redis,
		authz.CacheOptions{},
	)
	authzSvc = authz.NewService(authzBindings, newAuthzOrgAncestry(orgModule))
	wireAuthzCacheInvalidation(a, authzBindings)

	// Hybrid engine: Casbin owns role→permission (+ super_admin wildcard) and
	// is the authority consulted by Service.Check; the Go scopeCovers above
	// still decides instance scope (org ltree / group / kind). The enforcer
	// persists to the existing casbin_rule table and rebuilds from the
	// mxid_role* source of truth on boot + on role/permission/super-admin
	// mutations (wireCasbinSync). On any setup error we fall back to the
	// legacy in-binding permission set so a Casbin hiccup never takes down
	// the whole authz path.
	if casbinEngine, err := authz.NewCasbinEngineWithDB(a.DB); err != nil {
		a.Logger.Error("casbin engine init failed, using legacy perm matching: " + err.Error())
	} else {
		loader := newCasbinPolicyLoader(a)
		if err := casbinEngine.Sync(context.Background(), loader); err != nil {
			a.Logger.Error("casbin initial sync failed, using legacy perm matching: " + err.Error())
		} else {
			authzSvc = authzSvc.WithCasbin(casbinEngine)
			wireCasbinSync(workerCtx, a, casbinEngine, loader)
			// Safety net for dropped resync events: periodic full rebuild.
			go runCasbinReconcile(workerCtx, casbinEngine, loader, a.Logger)
		}
	}
	// Tell authn /auth/me whether the caller is admin-eligible so the
	// portal SPA renders the "switch to console" entry only for users
	// who can actually use it.
	authnModule.Handler.SetAdminChecker(func(ctx context.Context, tenantID, userID int64) bool {
		perms, err := authzSvc.PermissionsForUser(ctx, tenantID, userID)
		if err != nil {
			return false
		}
		return len(perms) > 0
	})

	// Mandatory-MFA-enrollment gate predicate: does the MFA policy require THIS
	// user to hold a factor? all → everyone; admin_only → console-eligible
	// admins; off → no one. Pairs with the EnrollGate middleware mounted above.
	mfaPolicyRequires := func(ctx context.Context, tenantID, userID int64) bool {
		pol, err := settingService.MFAPolicy(ctx, tenantID)
		if err != nil {
			return false
		}
		switch pol.Mode {
		case setting.MFAModeAll:
			return true
		case setting.MFAModeAdminOnly:
			if authzSvc == nil {
				return false
			}
			perms, err := authzSvc.PermissionsForUser(ctx, tenantID, userID)
			return err == nil && len(perms) > 0
		default:
			return false
		}
	}
	authnModule.Handler.SetMFAEnrollGate(mfaPolicyRequires)

	// Enforce mandatory MFA enrollment at the single session-creation chokepoint
	// so EVERY login method is covered — not just the local password handler.
	// SMS OTP, magic link and external IdP (Lark) all funnel through
	// SessionMgr.Create; without this they bypassed the enroll flag entirely and
	// a "force MFA for all" policy silently did nothing for federated users.
	// Only flag users who actually need to enrol (policy requires it AND they
	// hold no factor yet), so already-enrolled logins aren't needlessly gated.
	sessionMgr.SetEnrollDecider(func(ctx context.Context, tenantID, userID int64) bool {
		if !mfaPolicyRequires(ctx, tenantID, userID) {
			return false
		}
		hasMFA, err := authnModule.Engine.HasMFA(ctx, userID)
		return err == nil && !hasMFA
	})

	// External IdP is an EE feature: the implementation lives ONLY in the
	// private mxid-ee module and self-registers via pkg/ee/registry. CE imports
	// none of it, so RunInit is a no-op in this binary. We hand the EE side the
	// bootstrap App plus the CE-domain hooks it must not import directly:
	// external-login account linking (user domain), tenant-code resolution, and
	// the console authorization gate (the security boundary — a federated user
	// with no console permission, or a break-glass built-in, is rejected).
	if err := registry.RunInit(&registry.InitContext{
		App:           a,
		SessionMgr:    sessionMgr,
		ExternalLogin: newUserExternalResolver(userModule).Resolve,
		TenantByCode: func(ctx context.Context, code string) int64 {
			t, err := tenantModule.Service.GetByCode(ctx, code)
			if err != nil || t == nil {
				return 0
			}
			return t.ID
		},
		ConsoleGate: func(ctx context.Context, tenantID, userID int64) error {
			// Break-glass guard: seeded built-in accounts never federate.
			if u, err := userModule.Repo.GetByID(ctx, userID); err == nil && u != nil && u.IsBuiltin {
				return fmt.Errorf("builtin account must use local login")
			}
			// Admin authorization: must hold at least one console permission.
			perms, err := authzSvc.PermissionsForUser(ctx, tenantID, userID)
			if err != nil || len(perms) == 0 {
				return fmt.Errorf("not authorized for console")
			}
			return nil
		},
		// External-IdP start/callback run pre-login (public group, no tenant
		// scope), so inject the scope before the scoped settings read — same
		// tenant-scope fix as the login providers. Empty returns let the EE side
		// fall back to its boot-time env defaults.
		ExternalURLs: func(ctx context.Context, tenantID int64) (issuer, portal, console string) {
			ctx = tenantscope.WithTenant(ctx, tenantID)
			urls, err := settingService.ExternalURLs(ctx, tenantID)
			if err != nil {
				// ErrNotFound already returns (empty, nil) inside ExternalURLs, so a
				// non-nil err here is a genuine DB / decode failure. Empty return is
				// the intended fail-safe (the EE side falls back to its boot-time env
				// URLs), but swallowing the error silently hid DB blips that
				// downgraded the external-IdP issuer to the boot default with zero
				// signal. Log it so the degradation is observable.
				a.Logger.Warn("external-idp URL settings read failed; falling back to boot defaults",
					zap.Int64("tenant_id", tenantID), zap.Error(err))
				return "", "", ""
			}
			return urls.IssuerURL, urls.PortalURL, urls.ConsoleURL
		},
		// Let an EE feature bind a durable outbox handler. The neutral
		// payload-bytes signature is adapted onto the concrete outbox.Handler so
		// the EE module needs no CE internal type.
		OutboxRegister: func(kind string, h registry.OutboxHandler) {
			outboxWorker.Register(kind, func(ctx context.Context, msg *outbox.Message) error {
				return h(ctx, msg.Payload)
			})
		},
		// Decrypted per-app provisioning config read, for the EE SCIM connector.
		ProvisioningConfig: provisioningModule.Service.Resolved,
	}); err != nil {
		a.Logger.Fatal("init EE features", zap.Error(err))
	}

	// EE handlers (if any) are now registered — start the outbox worker.
	go outboxWorker.Run(workerCtx)

	// Audit hash-chain writer — single goroutine, single writer (Chainer's
	// own invariant: never run two of these against the same DB). Drains
	// mxid_audit_pending into the tamper-evident mxid_audit_entry chain.
	// The HMAC key is release-mode fail-closed in validateSecrets; a
	// non-empty-but-malformed value fails startup here rather than running
	// silently with a zero/garbage key that would produce an
	// unverifiable chain.
	auditChainKey, err := base64.StdEncoding.DecodeString(a.Config.Crypto.AuditChainKey)
	if err != nil {
		a.Logger.Fatal("decode crypto.audit_chain_key (set MXID_CRYPTO_AUDIT_CHAIN_KEY to base64(32 random bytes))", zap.Error(err))
	}
	if len(auditChainKey) == 0 {
		a.Logger.Fatal("crypto.audit_chain_key is empty; export MXID_CRYPTO_AUDIT_CHAIN_KEY=$(openssl rand -base64 32)")
	}
	chainer := audit.NewChainer(a.DB, auditChainKey, "default", a.Logger)
	// Single-writer: the chainer assigns contiguous seq numbers, so exactly one
	// replica may run it. The advisory-lock leader guarantees that across pods
	// (others idle until failover), preventing duplicate-seq PK collisions.
	go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyAuditChainer, a.Logger, func(ctx context.Context) {
		chainer.Run(ctx, 2*time.Second)
	})

	// Audit anchorer — periodically seals the un-anchored tail of each chain
	// into a signed Merkle root written to an external sink, so a full DB
	// compromise (including mxid_audit_entry) can still be caught against the
	// external record. Single goroutine, gated on audit.anchor_enabled;
	// key decode/validity errors fail startup rather than anchoring silently
	// with a bad key.
	if a.Config.Audit.AnchorEnabled {
		auditAnchorSeed, err := base64.StdEncoding.DecodeString(a.Config.Crypto.AuditAnchorKey)
		if err != nil {
			a.Logger.Fatal("decode crypto.audit_anchor_key (set MXID_CRYPTO_AUDIT_ANCHOR_KEY to base64(32-byte ed25519 seed))", zap.Error(err))
		}
		auditAnchorPriv, err := crypto.Ed25519FromSeed(auditAnchorSeed)
		if err != nil {
			a.Logger.Fatal("crypto.audit_anchor_key invalid", zap.Error(err))
		}
		auditAnchorSink := audit.NewFileSink(a.Config.Audit.AnchorSinkPath)
		anchorer := audit.NewAnchorer(a.DB, auditAnchorPriv, auditAnchorSink, a.IDGen, a.Logger)
		// Single-writer like the chainer: one replica anchors, others idle until
		// failover. Also avoids two pods writing anchors to their own local sinks.
		go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyAuditAnchorer, a.Logger, func(ctx context.Context) {
			anchorer.Run(ctx, 60*time.Second)
		})
	}

	// Mount the per-app provisioning config API on the console group.
	provisioningModule.RegisterRoutes(a)

	// 6. Protocol resolvers — bridge app/user repos to protocol layer.
	//
	// Issuer is the externally-reachable base URL (nginx :3500 in dev) where
	// SPs collect /protocol/saml/.../metadata and similar. NOT the backend
	// listen port. ExternalURLs setting (admin-configurable) wins at runtime
	// via urlswap.Provider; this is the fallback when no override exists.
	//
	// Dev default: nginx fronts the API on :3500. Override via env if a
	// different host/port is canonical.
	// Boot-time external issuer: MXID_ISSUER override > release server.issuer_url
	// > localhost:3500 dev default. See ServerConfig.ResolveBootIssuer. The admin
	// ExternalURLs setting still overrides this per-request via urlswap.
	issuer := a.Config.Server.ResolveBootIssuer(os.Getenv("MXID_ISSUER"))

	appResolver := buildAppResolver(appModule, a.Config.Tenant.DefaultID, a.MasterKey, a.Logger)
	idResolver := buildIdentityResolver(userModule, a)
	sessResolver := resolver.NewSessionResolver(a.Redis)
	tenantResolver := newDBTenantResolver(a)

	// 6.5. App access policy module (authorization layer).
	//
	// Wired before protocol modules because OIDC /authorize calls into
	// the AccessChecker adapter to gate code issuance.
	accessRepo := appaccess.NewRepository(a.DB)
	accessSvc := appaccess.NewService(accessRepo, a.IDGen, a.EventBus)
	accessSvc.SetLogger(a.Logger)
	// Clean up access policies whose subject group/org/role is deleted, so they
	// don't dangle as "(unknown)" rows or phantom allow/deny rules.
	accessSvc.SubscribeEvents()
	appaccess.SetMatcher(newAccessMatcher(a))
	accessHandler := appaccess.NewHandler(accessSvc, newAccessSubjectResolver(a), a.Config.Tenant.DefaultID)
	accessHandler.Register(a.ConsoleGroup)
	accessAdapter := &oidcAccessAdapter{svc: accessSvc}

	// 6.6. App role module — IdP-side role mapping. SPs receive
	// `app_roles` claim instead of writing JMESPath against `groups`.
	approleRepo := approle.NewRepository(a.DB)
	approleSvc := approle.NewService(approleRepo, a.IDGen, a.EventBus)
	approleHandler := approle.NewHandler(approleSvc, newAccessSubjectResolver(a), newAppLabelResolver(a), a.Config.Tenant.DefaultID)
	approleHandler.Register(a.ConsoleGroup)
	appRolesAdapter := &oidcAppRolesAdapter{svc: approleSvc}

	// 6.8. JIT privileged access (temporary, time-bound role elevation).
	//
	// Constructed below, AFTER the OIDC/SAML/CAS protocol handlers exist, so the
	// access service can be wired with a real CompositeTerminator that forces a
	// downstream session logout on grant revoke/expiry. See "JIT access service"
	// after the protocol-module registration.

	// 6.7. Referenced-entity tenant validators (Phase 2.6).
	//
	// Association handlers accept a referenced entity id (user/group/org/role/
	// app) from the request body and link it to a tenant-owned parent. The
	// parent is tenant-guarded, but the referent was not validated — letting an
	// admin plant a FOREIGN-tenant entity into their own org/group/role/app and
	// inherit its scoped access. Inject tenant-scoped existence checks (backed
	// by each referent's GetByID; the tenantscope plugin appends tenant_id=?, so
	// a cross-tenant id 404s) so every site rejects a foreign referent.
	userValidator := validateUserInTenant(userModule)
	groupValidator := validateGroupInTenant(groupModule)
	orgValidator := validateOrgInTenant(orgModule)
	roleValidator := validateRoleInTenant(permissionModule)
	appValidator := validateAppInTenant(appModule)
	appGroupValidator := validateAppGroupInTenant(appModule)

	orgModule.Service.SetUserValidator(userValidator)
	groupModule.Service.SetUserValidator(userValidator)
	permissionModule.Service.SetRefValidators(permission.RefValidators{
		User:  userValidator,
		Group: groupValidator,
		Org:   orgValidator,
	})
	// Enrich the role member list with subject display names (user/group/org)
	// so the console shows "who" instead of a raw snowflake id.
	permissionModule.Service.SetSubjectResolvers(subjectNameResolvers(userModule, groupModule, orgModule))
	// The built-in super_admin role is a façade over mxid_user.is_super_admin:
	// add/remove/list a member there grants/revokes/lists that flag.
	permissionModule.Service.SetSuperAdminManager(superAdminManagerAdapter{userM: userModule})
	appModule.Service.SetAccessSubjectValidators(app.AccessSubjectValidators{
		User:  userValidator,
		Group: groupValidator,
		Org:   orgValidator,
		Role:  roleValidator,
	})
	accessSvc.SetRefValidators(appaccess.RefValidators{
		App:      appValidator,
		AppGroup: appGroupValidator,
		User:     userValidator,
		Group:    groupValidator,
		Org:      orgValidator,
		Role:     roleValidator,
	})
	approleSvc.SetRefValidators(approle.RefValidators{
		App:      appValidator,
		AppGroup: appGroupValidator,
		User:     userValidator,
		Group:    groupValidator,
		Org:      orgValidator,
		Role:     roleValidator,
	})

	// 7. Register protocol modules
	//
	// OIDC engine: the zitadel/oidc-based provider (internal/protocol/oidcop)
	// is the sole OIDC engine, mounted unconditionally at /protocol/oidc.
	// oidcLogoutSvc is the WS2 back-channel logout fan-out service
	// (internal/protocol/oidclogout) that restores offboarding + JIT
	// downstream teardown (see the offboardLogout / oidcLogout dispatch
	// below).
	// Runtime URL provider — admin-configurable external URLs. Empty fields fall
	// through to the bootstrap config (the static defaults compiled in). Invoked
	// per-request so admin changes take effect immediately (settings cache 60s).
	// Defined here (before wireOIDCOP) so OIDC's issuer can honour the same
	// runtime override that SAML/CAS do below.
	urlProvider := func(ctx context.Context) urlswap.URLs {
		v, err := settingService.ExternalURLs(ctx, a.Config.Tenant.DefaultID)
		if err != nil {
			return urlswap.URLs{}
		}
		return urlswap.URLs{Issuer: v.IssuerURL, Portal: v.PortalURL, Console: v.ConsoleURL}
	}
	// oidcIssuerResolver maps a ctx to the OIDC issuer (issuer + /protocol/oidc)
	// from the runtime override, or "" to fall back to the static boot issuer.
	// Shared by the op provider (id_token/discovery `iss`) and the back-channel
	// logout signer (logout_token `iss`) so the two never disagree.
	oidcIssuerResolver := func(ctx context.Context) string {
		if u := urlProvider(ctx); u.Issuer != "" {
			return strings.TrimSuffix(u.Issuer, "/") + "/protocol/oidc"
		}
		return ""
	}

	oidcLogoutSvc, err := wireOIDCOP(workerCtx, a, issuer, appResolver, idResolver, sessResolver, sessionMgr, accessAdapter, tenantResolver, appRolesAdapter, oidcIssuerResolver)
	if err != nil {
		a.Logger.Fatal("wire zitadel OIDC engine: " + err.Error())
	}
	samlModule := saml.Register(a.ProtocolGroup, issuer, a.Config.Server.PortalURL, appResolver, idResolver, sessResolver, tenantResolver, saml.NewSessionIndexStore(a.Redis), appRolesAdapter, accessAdapter, a.Redis, a.Logger)
	casModule := cas.Register(a.ProtocolGroup, issuer, a.Config.Server.PortalURL, a.Redis, appResolver, idResolver, sessResolver, tenantResolver, appRolesAdapter, a.Logger)

	// One-click offboarding (L1 access cutoff): disable account + back-channel
	// logout the user's apps + kill all sessions. Wired here (after oidc) so it
	// can borrow the OIDC back-channel fan-out (oidcLogoutSvc, WS2).
	// Registered on the console group, which already carries the step-up MFA +
	// authz middleware chain.
	offboardLogout := offboarding.LogoutNotifierFunc(oidcLogoutSvc.LogoutUser)
	offboardFP := offboardFootprint{access: accessSvc, apps: appModule.Service, provisioning: provisioningModule.Service}
	offboardMod := offboarding.Register(a, userModule.Service, sessionMgr, offboardLogout, offboardFP)
	offboardMod.Service.SetWebhookDispatcher(offboardWebhookDispatcher{settings: settingService, outbox: outboxRepo})
	offboardMod.Service.SetDeprovisionEnqueuer(offboardDeprovisionEnqueuer{outbox: outboxRepo})
	offboardMod.RegisterRoutes(a)

	// urlProvider (defined above, before wireOIDCOP) also drives SAML/CAS.
	samlModule.Handler.SetURLProvider(urlProvider)
	casModule.Handler.SetURLProvider(urlProvider)

	// JIT access service (deferred from §6.8 until the protocol handlers exist).
	//
	// Runtime-gated by the conditional_access feature inside Register* (no
	// edition branch here — the schema is foundational/grandfathered, only the
	// capability is licence-gated). The service invalidates the requester's
	// authz binding cache (authzBindings) on approve/revoke/expire so the
	// elevated role goes live (and dies) without a re-login, and now also drives
	// a CompositeTerminator that forces a downstream session logout per app
	// protocol (OIDC back-channel / SAML IdP-initiated / CAS SLO) so the elevated
	// role can't outlive the grant inside the app's own session.
	//
	// The OIDC dispatcher is the WS2 oidclogout.Service fan-out.
	oidcLogout := oidcLogoutSvc.LogoutUserApp
	accessTerminator := access.NewCompositeTerminator(
		appProtocolResolver{svc: appModule.Service},
		oidcLogout,
		samlModule.Handler.IdPInitiatedLogout,
		casModule.Handler.SingleLogout,
		a.Logger,
	)
	accessJITRepo := access.NewRepository(a.DB, a.IDGen)
	accessJITSvc := access.NewServiceWithLogger(
		accessJITRepo,
		a.IDGen,
		a.EventBus,
		authzBindings, // *authz.CachedBindingProvider implements Invalidate(ctx,tid,uid) error
		newAccessSubjectMatcher(a),
		accessTerminator,
		a.Logger,
	)
	// Break-glass: super-admins are exempt from per-eligibility approver scoping
	// (they already approve anything via the wildcard authz policy).
	accessJITSvc.SetSuperAdminChecker(func(ctx context.Context, userID int64) bool {
		u, err := userModule.Repo.GetByID(ctx, userID)
		return err == nil && u != nil && u.IsSuperAdmin
	})
	accessJITHandler := access.NewHandler(accessJITSvc, a.Config.Tenant.DefaultID, authn.NewStepUpChecker(stepUpDeps))
	accessJITHandler.RegisterConsole(a.ConsoleGroup)
	accessJITHandler.RegisterPortal(a.PortalGroup)

	// Sweeper: end grants whose expires_at has passed (cache-bust + audit
	// event). context.Background() — there is no app lifecycle context.
	// Leader-only: without a claim, every replica sweeps the same due grants and
	// each publishes access.grant.expired, duplicating the tamper-evident audit
	// trail and double-firing downstream logout. One replica sweeps; others idle
	// until failover. StartSweeper spawns its own goroutine and returns, so the
	// leader callback blocks on ctx.Done() to hold leadership for its lifetime.
	go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyAccessSweeper, a.Logger, func(ctx context.Context) {
		access.StartSweeper(ctx, accessJITSvc, accessJITRepo, 30*time.Second, a.Logger)
		<-ctx.Done()
	})

	// Audit subscriptions — defense-in-depth over the catch-all RecordAPIRequest.
	// The access.* payloads self-describe via resource_type/resource_id, so the
	// payload-driven ResourceEventHandler attributes them correctly; the actor /
	// ip come from auditctx (request-fired events) or fall back to system (the
	// sweeper-fired access.grant.expired).
	for _, et := range []string{
		access.EventRequestCreated, access.EventRequestApproved, access.EventRequestRejected,
		access.EventRequestCancelled, access.EventGrantActivated, access.EventGrantExpired,
		access.EventGrantRevoked,
	} {
		a.EventBus.Subscribe(et, auditModule.Service.ResourceEventHandler(et, "access_request"))
	}
	// Eligibility (policy-config) writes self-describe as resource_type
	// "access_eligibility"; keep them on a separate default so a payload that
	// somehow omits the key still attributes to the right resource.
	for _, et := range []string{
		access.EventEligibilityCreated, access.EventEligibilityUpdated, access.EventEligibilityDeleted,
	} {
		a.EventBus.Subscribe(et, auditModule.Service.ResourceEventHandler(et, "access_eligibility"))
	}

	// 8. Register portal gateway (user-facing API)
	portalUserQ := buildPortalUserQuerier(userModule)
	portalAppQ := buildPortalAppQuerier(a, appModule, issuer, accessSvc)
	portalSessQ := buildPortalSessionQuerier(sessionMgr)
	portalMFAQ := buildPortalMFAQuerier(userModule)
	portalIDQ := buildPortalIdentityQuerier(userModule)
	portalConsentQ := buildPortalConsentQuerier(appModule)
	portal.Register(a.PortalGroup, portalUserQ, portalAppQ, portalSessQ, portalMFAQ, portalIDQ,
		consentModule.Service, portalConsentQ, a.Config.Tenant.DefaultID,
		a.Redis, a.Logger, a.Config.Server.PortalURL, mailerSvc, a.EventBus)

	// Public portal password-reset routes (no auth). Lives on
	// /api/v1/portal-public so the AuthMiddleware on /api/v1/portal can't
	// reject the pre-login caller.
	tenantByCodeResolver := func(ctx context.Context, code string) int64 {
		t, err := tenantModule.Service.GetByCode(ctx, code)
		if err != nil || t == nil {
			return 0
		}
		return t.ID
	}
	// Brute-force / abuse limiters for the public pre-auth flows. Each is
	// fail-closed (a Redis outage blocks rather than admits) and keyed by the
	// flow's natural identifier (phone / email). buildLimiter logs + returns
	// nil on a config error so wiring degrades gracefully.
	smsLoginLimiter := buildLimiter(a, ratelimit.Config{
		Purpose: "sms_login", MaxAttempts: 5,
		Window: 5 * time.Minute, Lockout: 15 * time.Minute,
	})
	magicLinkLimiter := buildLimiter(a, ratelimit.Config{
		Purpose: "magic_link_send", MaxAttempts: 5,
		Window: 15 * time.Minute, Lockout: 15 * time.Minute,
	})
	pwdResetLimiter := buildLimiter(a, ratelimit.Config{
		Purpose: "pwd_reset_send", MaxAttempts: 5,
		Window: 15 * time.Minute, Lockout: 15 * time.Minute,
	})

	// devFallback gates the dev_link/dev_code response + log exposure on
	// non-release mode. In release we never leak the out-of-band reset/magic
	// /OTP secret even when the mail/SMS provider is misconfigured or fails.
	devFallback := !a.Config.Server.IsRelease()
	pwdResetHandler := portal.NewPasswordResetHandler(
		a.Redis, portalUserQ, a.Logger, a.Config.Server.PortalURL,
		mailerSvc, a.Config.Tenant.DefaultID, tenantByCodeResolver,
	)
	pwdResetHandler.SetLimiter(pwdResetLimiter)
	pwdResetHandler.SetDevFallback(devFallback)
	portal.RegisterPasswordResetRoutes(publicPortalGroup, pwdResetHandler)
	// Public SMS OTP routes. Gated by LoginMethods.SMSOTP. Provider config
	// (Aliyun / Tencent / Twilio) is per-tenant via setting.SMS; secret is
	// AES-decrypted by setting.Service.SMS at send time.
	smsSvc := sms.New(settingService)
	portal.RegisterSMSOTPRoutes(publicPortalGroup, portal.NewSMSOTPHandler(portal.SMSOTPHandlerOpts{
		Redis:      a.Redis,
		Users:      portalUserQ,
		Logger:     a.Logger,
		SMS:        smsSvc,
		SessionMgr: sessionMgr,
		Enabled: func(ctx context.Context) bool {
			m, err := settingService.LoginMethods(ctx, a.Config.Tenant.DefaultID)
			if err != nil {
				return false
			}
			return m.SMSOTP
		},
		DefaultTID:   a.Config.Tenant.DefaultID,
		TenantByCode: tenantByCodeResolver,
		CookieDomain: a.Config.Session.CookieDomain,
		CookieSecure: a.Config.Session.CookieSecure,
		DevFallback:  devFallback,
		Limiter:      smsLoginLimiter,
	}))

	// Public magic-link routes. Gated by LoginMethods.EmailMagicLink — the
	// send endpoint returns 403 when admin disabled it. Callback always
	// honors live tokens regardless of the flag.
	portal.RegisterMagicLinkRoutes(publicPortalGroup, portal.NewMagicLinkHandler(portal.MagicLinkHandlerOpts{
		Redis:      a.Redis,
		Users:      portalUserQ,
		Logger:     a.Logger,
		PortalURL:  a.Config.Server.PortalURL,
		Mailer:     mailerSvc,
		SessionMgr: sessionMgr,
		Enabled: func(ctx context.Context) bool {
			m, err := settingService.LoginMethods(ctx, a.Config.Tenant.DefaultID)
			if err != nil {
				return false
			}
			return m.EmailMagicLink
		},
		DefaultTID:   a.Config.Tenant.DefaultID,
		TenantByCode: tenantByCodeResolver,
		CookieDomain: a.Config.Session.CookieDomain,
		CookieSecure: a.Config.Session.CookieSecure,
		DevFallback:  devFallback,
		Limiter:      magicLinkLimiter,
	}))

	// 9. Mount /security on BOTH portal and console groups so the rate
	//    limiter (shared via authnModule.Engine.MFARateLimiter()) is
	//    threaded into both copies of the handler. portal.Register no
	//    longer mounts /security itself — keeping the wiring in one place
	//    avoids a "two sources of truth" footgun when the handler signature
	//    grows.
	mfaLimiter := authnModule.Engine.MFARateLimiter()
	// Wire admin "clear MFA lockout" → reset Redis counters via the same
	// limiter the login + enroll paths use.
	userModule.Service.SetMFALockoutClearer(func(ctx context.Context, uid int64) {
		mfaLimiter.Reset(ctx, uid, "")
	})
	// TOTP single-use (replay) protection. Every VerifyTOTP call site (login
	// MFA challenge, step-up, enroll/re-verify) routes through
	// user.Service.VerifyTOTP, so this one wiring covers them all.
	userModule.Service.SetTOTPReplayGuard(a.Redis)
	portalLoginHistoryQ := buildPortalLoginHistoryQuerier(auditModule)
	apiTokenModule := apitoken.Register(a)
	portalAPITokenQ := buildPortalAPITokenQuerier(apiTokenModule.Service)
	tenantDefault := a.Config.Tenant.DefaultID
	portal.RegisterSecurityRoutes(a.PortalGroup, portal.NewSecurityHandler(
		session.NamespacePortal, portalUserQ, portalSessQ, portalMFAQ, portalIDQ,
		portalLoginHistoryQ, portalAPITokenQ, tenantDefault, mfaLimiter, a.EventBus,
	))
	portal.RegisterSecurityRoutes(a.ConsoleGroup, portal.NewSecurityHandler(
		session.NamespaceConsole, portalUserQ, portalSessQ, portalMFAQ, portalIDQ,
		portalLoginHistoryQ, portalAPITokenQ, tenantDefault, mfaLimiter, a.EventBus,
	))

	// Mount the bearer middleware on /openapi/v1 so every script-facing
	// route requires a valid PAT. Per-route scope guards (apitoken.RequireScope)
	// can be added when concrete routes ship.
	a.OpenAPIGroup.Use(apitoken.AuthMiddleware(apiTokenModule.Service))

	// Minimal /me probe — proves the bearer middleware fires AND lets
	// scripts discover their own identity/scopes before making real
	// calls. Lives here (not in a domain package) because it's pure
	// glue: read context, echo back.
	a.OpenAPIGroup.GET("/me", func(c *gin.Context) {
		userID, _ := c.Get(apitoken.CtxUserID)
		tenantID, _ := c.Get(apitoken.CtxTenantID)
		scopes, _ := c.Get(apitoken.CtxScopes)
		c.JSON(200, gin.H{
			"code": 0, "message": "ok",
			"data": gin.H{"user_id": userID, "tenant_id": tenantID, "scopes": scopes},
		})
	})

	// 10. Mirror /profile + /profile/email/* onto console so admin users
	//     can edit their own display name / avatar / email and trigger
	//     email verification from the console SPA. Verification click-back
	//     redirect still points at the portal URL — admins clicking the
	//     dev_link land in the portal, which is fine (single account state).
	portal.RegisterProfileRoutes(a.ConsoleGroup, portal.NewProfileHandler(portalUserQ, a.EventBus))
	emailVerifyHandler := portal.NewEmailVerifyHandler(
		a.Redis, portalUserQ, a.Logger, a.Config.Server.PortalURL, mailerSvc, tenantDefault,
	)
	emailVerifyHandler.SetDevFallback(devFallback)
	portal.RegisterEmailVerifyRoutes(a.ConsoleGroup, emailVerifyHandler)

	// Populate the deny-by-default gateway registry now that every console route
	// is mounted: Protect the admin surface, allow-list self-service + public
	// routes, and audit coverage. Hard mode (AuditOnly:false at the gateway
	// above) relies on this map being complete before the first request.
	registerConsoleAuthz(a)
}

// buildPortalConsentQuerier surfaces a thin app-domain projection to the
// consent handler so it can render app metadata on the consent screen
// without coupling the portal handler to the app domain types.
func buildPortalConsentQuerier(appModule *app.Module) portal.ConsentQuerier {
	return portalConsentQuerierAdapter{appModule: appModule}
}

type portalConsentQuerierAdapter struct {
	appModule *app.Module
}

func (a portalConsentQuerierAdapter) GetApp(ctx context.Context, appID int64) (*portal.ConsentApp, error) {
	ap, err := a.appModule.Repo.GetByID(ctx, appID)
	if err != nil {
		return nil, err
	}
	out := &portal.ConsentApp{ID: ap.ID, Name: ap.Name}
	if ap.Description != nil {
		out.Description = *ap.Description
	}
	if ap.Icon != nil {
		out.LogoURL = *ap.Icon
	}
	if ap.HomeURL != nil {
		out.HomeURL = *ap.HomeURL
	}
	return out, nil
}

// buildLimiter constructs a fail-closed ratelimit.Limiter from the app's
// shared redis client, logging and returning nil on a config error so the
// caller's wiring degrades to "no limiter" rather than panicking at boot.
func buildLimiter(a *bootstrap.App, cfg ratelimit.Config) *ratelimit.Limiter {
	l, err := ratelimit.New(a.Redis, cfg)
	if err != nil {
		a.Logger.Error("rate limiter init failed for " + cfg.Purpose + ": " + err.Error())
		return nil
	}
	return l
}

// buildAppResolver creates an AppResolver that bridges the app domain repo.
//
// Cert adapters decrypt the at-rest private_key via the bootstrap master key
// before handing it to the protocol layer. The protocol layer never sees
// the ciphertext.
func buildAppResolver(appModule *app.Module, _ int64, masterKey *crypto.MasterKey, logger *zap.Logger) resolver.AppResolver {
	convertCert := func(c *app.AppCert) (*resolver.CertConfig, error) {
		cfg := &resolver.CertConfig{
			ID:         c.ID,
			AppID:      c.AppID,
			CertType:   c.CertType,
			Algorithm:  c.Algorithm,
			PublicKey:  c.PublicKey,
			PrivateKey: c.PrivateKey,
			NotBefore:  &c.NotBefore,
			ExpiresAt:  c.ExpiresAt,
			Status:     c.Status,
		}
		if c.KID != nil {
			cfg.KID = *c.KID
		}
		if c.Encrypted {
			plain, err := masterKey.Decrypt(c.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt app cert %d: %w", c.ID, err)
			}
			cfg.PrivateKey = string(plain)
		}
		return cfg, nil
	}

	return resolver.NewAppResolver(
		// GetByCode
		func(ctx context.Context, tenantID int64, code string) (*resolver.AppConfig, error) {
			// The protocol layer is the cross-tenant entry point: it discovers
			// the tenant FROM the app (by globally-unique client_id / code /
			// app_id), so app/cert resolution runs as an explicit cross-tenant
			// read. The resolved AppConfig carries its TenantID, which the
			// protocol handlers then use to scope downstream user/consent reads.
			ctx = tenantscope.WithCrossTenant(ctx)
			a, err := appModule.Repo.GetByCode(ctx, tenantID, code)
			if err != nil {
				return nil, err
			}
			return appToConfig(a), nil
		},
		// GetByID
		func(ctx context.Context, appID int64) (*resolver.AppConfig, error) {
			ctx = tenantscope.WithCrossTenant(ctx)
			a, err := appModule.Repo.GetByID(ctx, appID)
			if err != nil {
				return nil, err
			}
			return appToConfig(a), nil
		},
		// GetByClientID
		func(ctx context.Context, clientID string) (*resolver.AppConfig, error) {
			ctx = tenantscope.WithCrossTenant(ctx)
			a, err := appModule.Repo.GetByClientID(ctx, clientID)
			if err != nil {
				return nil, err
			}
			return appToConfig(a), nil
		},
		// GetCert — return the currently-active cert of the requested type.
		func(ctx context.Context, appID int64, certType string) (*resolver.CertConfig, error) {
			ctx = tenantscope.WithCrossTenant(ctx)
			certs, err := appModule.Repo.ListCertsByApp(ctx, appID)
			if err != nil {
				return nil, err
			}
			for _, c := range certs {
				if c.CertType == certType && c.Status == app.CertStatusActive {
					return convertCert(c)
				}
			}
			return nil, fmt.Errorf("no active cert of type %s for app %d", certType, appID)
		},
		// ListCerts — used by per-app cert listing; returns active + rotating.
		func(ctx context.Context, appID int64) ([]*resolver.CertConfig, error) {
			certs, err := appModule.Repo.ListCertsByApp(ctx, appID)
			if err != nil {
				return nil, err
			}
			result := make([]*resolver.CertConfig, 0, len(certs))
			for _, c := range certs {
				if c.Status != app.CertStatusActive && c.Status != app.CertStatusRotating {
					continue
				}
				converted, err := convertCert(c)
				if err != nil {
					return nil, err
				}
				result = append(result, converted)
			}
			return result, nil
		},
		// ListAllActiveSigningCerts — IdP-level JWKS aggregation.
		func(ctx context.Context) ([]*resolver.CertConfig, error) {
			certs, err := appModule.KeyService.ListActiveSigningCerts(ctx)
			if err != nil {
				return nil, err
			}
			result := make([]*resolver.CertConfig, 0, len(certs))
			for _, c := range certs {
				converted, err := convertCert(c)
				if err != nil {
					// One unusable cert (e.g. orphaned by a KEK rotation) must
					// not take down the whole IdP JWKS for every other app.
					// Skip it — a key we can't load is a key we can't sign with,
					// so it has no business being advertised — and log loudly so
					// the operator knows to rotate that app's signing key.
					logger.Warn("skipping unusable signing cert in JWKS aggregation",
						zap.Int64("cert_id", c.ID), zap.Int64("app_id", c.AppID), zap.Error(err))
					continue
				}
				result = append(result, converted)
			}
			return result, nil
		},
		// MintSigningCert — lazy bootstrap for SAML/CAS apps created before
		// auto-mint existed. Called from the SAML metadata handler when no
		// signing cert is present, so /metadata never returns 500.
		func(ctx context.Context, appID int64) (*resolver.CertConfig, error) {
			cert, err := appModule.KeyService.RotateForApp(ctx, appID)
			if err != nil {
				return nil, err
			}
			return convertCert(cert)
		},
	)
}

func appToConfig(a *app.App) *resolver.AppConfig {
	// Shared apps (Scope=2) have NULL tenant_id; the protocol resolver
	// needs a concrete int — fall back to 0 to signal "no tenant scope".
	var tid int64
	if a.TenantID != nil {
		tid = *a.TenantID
	}
	cfg := &resolver.AppConfig{
		ID:              a.ID,
		TenantID:        tid,
		Scope:           a.Scope,
		SubjectStrategy: a.SubjectStrategy,
		Name:            a.Name,
		Code:            a.Code,
		Protocol:        a.Protocol,
		ClientType:      a.ClientType,
		Status:          a.Status,
		FirstParty:      a.IsFirstParty,
		RequireConsent:  a.RequireConsent,
		ProtocolConfig:  a.ProtocolConfig,
		RedirectURIs:    resolver.ParseRedirectURIs(a.RedirectURIs),
		AccessPolicy:    a.AccessPolicy,
	}
	if a.ClientID != nil {
		cfg.ClientID = *a.ClientID
	}
	if a.ClientSecret != nil {
		cfg.ClientSecret = *a.ClientSecret
	}
	if a.HomeURL != nil {
		cfg.HomeURL = *a.HomeURL
	}
	if a.LoginURL != nil {
		cfg.LoginURL = *a.LoginURL
	}
	if a.LogoutURL != nil {
		cfg.LogoutURL = *a.LogoutURL
	}
	return cfg
}

// certToConfig is kept for tests / future migrations that need a no-decrypt
// projection. Production code paths go through buildAppResolver's adapter
// which decrypts at-rest ciphertext.
var _ = (*resolver.CertConfig)(nil)

// buildIdentityResolver bridges the user domain repo to the protocol
// IdentityResolver so claim mappers can read user attributes without
// importing the user package.
func buildIdentityResolver(userModule *user.Module, a *bootstrap.App) resolver.IdentityResolver {
	return resolver.NewIdentityResolver(
		func(ctx context.Context, userID int64) (*resolver.IdentityInfo, error) {
			u, err := userModule.Repo.GetByID(ctx, userID)
			if err != nil {
				return nil, err
			}
			info := &resolver.IdentityInfo{
				ID:            u.ID,
				TenantID:      u.TenantID,
				Username:      u.Username,
				Status:        u.Status,
				UpdatedAt:     u.UpdatedAt.Unix(),
				EmailVerified: u.EmailVerified,
			}
			if u.DisplayName != nil {
				info.DisplayName = *u.DisplayName
			}
			if u.Email != nil {
				info.Email = *u.Email
			}
			if u.Phone != nil {
				info.Phone = *u.Phone
			}
			if u.Avatar != nil {
				info.Avatar = *u.Avatar
			}

			// OIDC `groups` claim emits machine-readable group codes (e.g.
			// "grafana-admins"), not display names. Downstream apps
			// (Grafana role_attribute_path, Harbor admin group, etc) all
			// match on identifiers, not localized names.
			var codes []string
			_ = a.DB.WithContext(ctx).
				Table("mxid_user_group_member m").
				Joins("INNER JOIN mxid_user_group g ON g.id = m.group_id AND g.deleted_at IS NULL").
				Where("m.user_id = ?", userID).
				Pluck("g.code", &codes).Error
			if codes == nil {
				codes = []string{}
			}
			info.Groups = codes

			// Pull user_detail (sparse) for claim-mapper access.
			var detail struct {
				Gender     *int    `gorm:"column:gender"`
				Birthday   *string `gorm:"column:birthday"`
				Address    *string `gorm:"column:address"`
				EmployeeNo *string `gorm:"column:employee_no"`
				JobTitle   *string `gorm:"column:job_title"`
				Department *string `gorm:"column:department"`
			}
			if err := a.DB.WithContext(ctx).
				Table("mxid_user_detail").
				Where("user_id = ?", userID).
				Take(&detail).Error; err == nil {
				m := map[string]any{}
				if detail.Gender != nil {
					m["gender"] = *detail.Gender
				}
				if detail.Birthday != nil {
					m["birthday"] = *detail.Birthday
				}
				if detail.Address != nil {
					m["address"] = *detail.Address
				}
				if detail.EmployeeNo != nil {
					m["employee_no"] = *detail.EmployeeNo
				}
				if detail.JobTitle != nil {
					m["job_title"] = *detail.JobTitle
				}
				if detail.Department != nil {
					m["department"] = *detail.Department
				}
				info.Detail = m
			}

			return info, nil
		},
	)
}

// OIDC adapters moved to adapters_oidc.go.

// runAuditRetention runs forever, purging audit_log rows older than
// AuditPolicy.RetentionDays every 6 hours. A zero RetentionDays disables
// the purge for that tick (admin can opt out by setting 0). Cron lives in
// the binary process, not a separate worker, so OSS deployments don't have
// to wire a job scheduler.
func runAuditRetention(stopCtx context.Context, a *bootstrap.App, ss *setting.Service, repo audit.Repository) {
	const tickEvery = 6 * time.Hour
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()
	// One immediate tick so a freshly-restarted server reflects the policy
	// without a 6h delay; later ticks ride the ticker.
	for {
		// Background cron with no request context. The purge is a deliberate
		// GLOBAL cross-tenant delete of old rows, so it must use an EXPLICIT
		// system escape — otherwise the tenant-isolation plugin fails closed
		// (or, worse, scopes the purge to tenant 0). SystemContext is the
		// sanctioned, auditable bypass for background jobs.
		ctx := tenantscope.SystemContext()
		metrics.WorkerRun("audit_retention")
		passOK := true
		pol, err := ss.AuditPolicy(ctx, a.Config.Tenant.DefaultID)
		if err != nil {
			passOK = false
		} else if pol.RetentionDays > 0 {
			cutoff := time.Now().AddDate(0, 0, -pol.RetentionDays)
			deleted, err := repo.PurgeOlderThan(ctx, cutoff)
			if err != nil {
				passOK = false
				a.Logger.Warn("audit retention purge failed",
					zap.Int("retention_days", pol.RetentionDays),
					zap.Error(err))
			} else if deleted > 0 {
				a.Logger.Info("audit retention purge",
					zap.Int("retention_days", pol.RetentionDays),
					zap.Int64("deleted", deleted))
			}
		}
		if passOK {
			metrics.WorkerSuccess("audit_retention")
		}
		select {
		case <-stopCtx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runHousekeepingPurge periodically hard-deletes rows that only ever grow:
// expired/revoked API tokens (already rejected at auth time) and old login
// history. Neither carries live security state, so this is pure GC to bound
// table size. Both are global cross-tenant DELETEs → explicit system context
// (the tenant plugin fails closed otherwise). First pass runs immediately;
// later passes ride the daily ticker.
func runHousekeepingPurge(stopCtx context.Context, a *bootstrap.App, tokenRepo apitoken.Repository, userRepo user.Repository) {
	const (
		tickEvery       = 24 * time.Hour
		tokenGrace      = 30 * 24 * time.Hour  // keep dead tokens 30d before purging
		loginRecordKeep = 365 * 24 * time.Hour // keep 1y of login history
	)
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()
	for {
		ctx := tenantscope.SystemContext()
		now := time.Now()

		metrics.WorkerRun("api_token_purge")
		if deleted, err := tokenRepo.PurgeExpired(ctx, now.Add(-tokenGrace)); err != nil {
			a.Logger.Warn("api token purge failed", zap.Error(err))
		} else {
			if deleted > 0 {
				a.Logger.Info("api token purge", zap.Int64("deleted", deleted))
			}
			metrics.WorkerSuccess("api_token_purge")
		}

		metrics.WorkerRun("login_record_purge")
		if deleted, err := userRepo.PurgeLoginRecordsOlderThan(ctx, now.Add(-loginRecordKeep)); err != nil {
			a.Logger.Warn("login record purge failed", zap.Error(err))
		} else {
			if deleted > 0 {
				a.Logger.Info("login record purge", zap.Int64("deleted", deleted))
			}
			metrics.WorkerSuccess("login_record_purge")
		}

		select {
		case <-stopCtx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runDynamicGroupReconcile periodically recomputes every dynamic group in the
// tenant. Membership is normally kept fresh by org/user domain events, but this
// is the ONLY reconciliation path: a dropped or lost event would otherwise leave
// a rule-based group stale until an unrelated event fires or an admin re-syncs
// by hand. The first pass runs immediately (heals drift accumulated while the
// server was down); later passes ride the ticker. Runs under an explicit tenant
// scope because ResyncTenantDynamicGroups touches tenant-scoped models.
func runDynamicGroupReconcile(stopCtx context.Context, grp *group.Service, tenantID int64) {
	const tickEvery = 30 * time.Minute
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()
	for {
		ctx := tenantscope.WithTenant(context.Background(), tenantID)
		metrics.WorkerRun("dynamic_group_reconcile")
		grp.ResyncTenantDynamicGroups(ctx, tenantID)
		metrics.WorkerSuccess("dynamic_group_reconcile")
		select {
		case <-stopCtx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runCasbinReconcile periodically rebuilds the Casbin enforcer policy from the
// mxid_role* source of truth. The policy is normally kept fresh by role /
// permission / super-admin events (wireCasbinSync), but that is purely
// event-driven: a dropped resync message (Redis blip, pod restart mid-publish)
// would leave the enforcer stale until the next relevant mutation or a restart —
// silently granting or denying against an outdated role→permission catalog. This
// is the safety net, mirroring runDynamicGroupReconcile. Sync is fail-safe: a
// loader error leaves the existing policy untouched (never degrades to
// deny-all), so a transient DB hiccup on a tick is harmless. The first pass is
// skipped here because the caller already ran an initial Sync at wire time.
func runCasbinReconcile(stopCtx context.Context, engine *authz.CasbinEngine, loader authz.PolicyLoader, logger *zap.Logger) {
	const tickEvery = 30 * time.Minute
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()
	for {
		select {
		case <-stopCtx.Done():
			return
		case <-ticker.C:
		}
		// context.Background (not tenant-scoped): the loader reads the full
		// role/permission catalog across the install, matching the boot-time Sync.
		metrics.WorkerRun("casbin_reconcile")
		if err := engine.Sync(context.Background(), loader); err != nil {
			// Existing policy is retained on error; log so a persistent failure
			// (vs a one-off blip) is visible.
			logger.Warn("casbin periodic reconcile failed; keeping current policy", zap.Error(err))
		} else {
			metrics.WorkerSuccess("casbin_reconcile")
		}
	}
}

// ensureInstallUUID returns this installation's stable UUID, generating and
// persisting one (as a setting) on first boot. Combined with the PostgreSQL
// system_identifier it forms the installation fingerprint for install-bound
// licenses. Returns "" only if persistence fails.
func ensureInstallUUID(svc *platformconfig.Service, logger *zap.Logger) string {
	var v struct {
		UUID string `json:"uuid"`
	}
	err := svc.Get(context.Background(), platformconfig.KeyInstallUUID, &v)
	if err != nil && err != platformconfig.ErrNotFound {
		// A real read error (not first-boot): do NOT regenerate — that would
		// rotate the fingerprint and break install-bound licenses. The platform
		// table is not tenant-scoped, so a scope-less boot read no longer fails
		// closed; any error here is a genuine DB problem.
		logger.Error("read install uuid failed; not regenerating", zap.Error(err))
		return ""
	}
	if v.UUID == "" {
		v.UUID = uuid.NewString()
		if err := svc.Set(context.Background(), platformconfig.KeyInstallUUID, v); err != nil {
			logger.Warn("persist install uuid failed", zap.Error(err))
			return ""
		}
	}
	return v.UUID
}
