# Architecture

Reading order: start with the [README architecture diagram](../README.md#architecture), then come here for the deeper breakdown of why each layer exists and where to extend it.

## Process layout

MXID is one Go binary serving:

- Backend REST API at `/api/v1/{console,portal,openapi}/...`
- Public bootstrap endpoint at `/api/v1/system/bootstrap` (pre-auth)
- Protocol gateway at `/protocol/{oidc,saml,cas,jwt}/...`
- Static console + portal SPAs (mounted in production builds)

The SPAs are independent pnpm workspaces (`web/apps/{console,portal}`) sharing a third workspace (`web/packages/shared`) for API client, i18n, and UI primitives.

## Layered packages

```
cmd/server/                  binary entrypoint + thin adapter glue (1 file ~700 LOC, intentional god-file per project memory)
└── internal/
    ├── bootstrap/           viper config, gorm wiring, snowflake IDs, router, structured logger
    ├── domain/              one package per business capability
    │   ├── user/            local accounts, MFA, password history
    │   ├── tenant/          multi-tenant model
    │   ├── app/             SP registration + protocol_config + access policy
    │   ├── authn/           login orchestration, captcha, MFA challenge, login policy
    │   ├── audit/           append-only log + retention
    │   ├── setting/         hot-reload runtime config (the central knob)
    │   ├── consent/         OIDC scope consent grants
    │   ├── appaccess/       per-app allow/deny rules
    │   ├── approle/         per-app role bindings
    │   ├── externalidp/     Lark / Feishu / Teams (and any others added via providers/)
    │   ├── apitoken/        headless API tokens
    │   ├── org/             org tree (departments)
    │   ├── group/           static + dynamic user groups
    │   ├── permission/      role-based authz primitive
    │   └── upload/          binary asset store (icons / logos → mxid_upload, bytea, ≤2 MB)
    ├── protocol/            stateless protocol handlers
    │   ├── oidc/            authorize, token, userinfo, revoke, introspect, end_session, jwks, discovery
    │   ├── saml/            metadata, sso (POST + redirect bindings), slo
    │   ├── cas/             login, validate, serviceValidate, p3/serviceValidate, logout
    │   └── resolver/        AppResolver / IdentityResolver / SessionResolver / TenantResolver — interfaces protocols use to read domain state without importing domain packages
    ├── gateway/             HTTP boundary
    │   ├── console/         admin REST surface (CRUD over domain)
    │   └── portal/          end-user REST + SSO bounce + magic-link / SMS / password-reset
    └── middleware/          cors, structured logger, request-id propagation
└── pkg/                     reusable libs
    ├── event/               in-process pub-sub bus
    ├── mailer/              SMTP + Go text/template templates
    ├── sms/                 Aliyun / Tencent / Twilio senders
    ├── session/             redis-backed session manager
    ├── urlswap/             canonical-URL resolution (admin setting → defaults → request-host swap)
    ├── snowflake/           globally unique IDs
    ├── crypto/              AES + bcrypt helpers
    └── authz/               role + scope check primitives
```

### Why this shape

- **Domain packages own their model + service + repository**. They expose narrow interfaces. Gateways import domain services; domain packages never import gateways.
- **Protocol handlers are stateless** and read state through `resolver` interfaces. Adding a new protocol (e.g. WS-Federation) means a new `internal/protocol/wsfed/` package and a few adapter functions wired in `cmd/server`.
- **Setting domain is the runtime config bus**. Every operationally-adjustable knob lives here. Handlers read settings via per-tenant accessors. Admin UI is a CRUD over the same shape. No restart required for any operational change.
- **`pkg/` is for libraries that don't know about MXID's business model**. Anything in `pkg/` could theoretically be open-sourced as a separate dependency.
- **`upload` domain keeps binary assets in the database** (`mxid_upload`, `bytea`). Served with `ETag` + `Cache-Control: immutable` so browsers get one-hit caching without a CDN. The side-effect: the backend carries zero local file state → no PVC needed on Kubernetes, no asset loss on container restart, and all replicas are consistent.

## Data flow — OIDC authorization code

```
Browser                Portal SPA            MXID backend                  External SP
   │                       │                       │                            │
   │  click "Login w/MXID" │                       │                            │
   ├──────────────────────────────────────────────────────────────────────────► │
   │                       │                       │                            │
   │ ◄────302 to /protocol/oidc/authorize?...─────────────────────────────────┤
   │                       │                       │                            │
   ├─/protocol/oidc/authorize─────────────────────►│                            │
   │                       │                       │                            │
   │ ◄─302 to /login?return_to=...─────────────────┤  (no session)              │
   │                       │                       │                            │
   ├─GET /login───────────►│                       │                            │
   │                       │                       │                            │
   ├─POST /api/v1/portal/auth/login ─────────────► │  authn.engine: pwd + MFA  │
   │                       │                       │                            │
   │ ◄────── 200 (cookie set) ─────────────────────│                            │
   │                       │                       │                            │
   ├─window.location.replace(return_to)─►          │                            │
   │                       │                       │                            │
   ├─/protocol/oidc/authorize (with cookie)──────► │  consent + access check    │
   │                       │                       │                            │
   │ ◄─302 to SP's redirect_uri?code=…─────────────│                            │
   │                       │                       │                            │
   ├─SP redirect_uri?code=…──────────────────────────────────────────────────► │
   │                       │                       │                            │
   │                       │                       │ ◄─POST /protocol/oidc/token (server-side)
   │                       │                       ├──────►id_token + access_token
   │                       │                       │                            │
   │ ◄─SP's "logged in" page──────────────────────────────────────────────────│
```

CAS and SAML follow the same general shape with protocol-specific details.

## Settings domain — the hot-reload bus

Operational config is split into typed groups:

| Group | Reads | Writes (UI) |
|-------|-------|-------------|
| `MailSMTP` | `pkg/mailer` per send | Settings → SMTP |
| `MailTemplates` | `pkg/mailer` template render | Settings → Mail Templates |
| `SecurityPolicy` | `authn.engine` for lockout, `user.Service` for password rules, `session.Manager` for TTL | Settings → Security |
| `LoginMethods` | portal login UI + authn.engine method gate | Settings → Login methods |
| `Branding` | portal /bootstrap → SPA applies primary color, title, custom CSS | Settings → Branding |
| `Localization` | portal /bootstrap → i18n default + tz | Settings → Localization |
| `ProtocolDefaults` | `app.Service.Create` applies on new apps | Settings → Protocol defaults |
| `SMS` | `pkg/sms` per send | Settings → SMS |
| `AuditPolicy` | retention cron + alert dispatch | Settings → Audit |
| `ExternalURLs` | every protocol handler via `urlswap.Resolve`; IdP callback / post-login redirect URLs resolved at runtime from this setting (no env required) | Settings → External URLs |

Sensitive fields (SMTP password, SMS secret) are AES-encrypted with `MXID_MASTER_KEY` at write time, decrypted on read. The encryption pipeline is in `setting.Service` — adding a new sensitive field requires only registering it in `sensitiveFields`.

## Platform-level config — physical isolation from tenant settings

Certain records must be read **before** a tenant context is known — most notably the license token and the installation fingerprint (`install_uuid`). These live in a dedicated table `mxid_platform_config` rather than in the tenant-scoped `mxid_setting` table. The reason is structural: the GORM `tenantscope` plugin is fail-closed by design; if a query runs without a tenant scope it silently returns no rows instead of the intended row. Placing license / fingerprint data in `mxid_setting` would cause them to be invisible at startup time and during login (before any tenant is resolved), leading to silent fallback values and install-fingerprint drift across restarts.

`mxid_platform_config` is **not** partitioned by `tenant_id`. Reads require no scope and are safe at any lifecycle phase.

## Tenant scope — automatic scope injection for unscoped setting reads

The `tenantscope` GORM plugin is fail-closed: queries that lack a scope return empty results rather than leaking cross-tenant data. This is correct for data rows but caused a category of silent bugs in the `setting` domain — functions like `getRaw` called before or outside a request context (startup, login flow, scheduled tasks) produced empty rows and fell back to defaults.

The fix is applied in `setting.getRaw`: when the GORM context carries no tenant scope, the function injects one explicitly using the tenant ID supplied to the call. Queries that already carry a scope (including `cross-tenant` / `system` scopes) are left untouched. This single change uniformly resolves all pre-authentication and background-task setting reads without weakening the fail-closed guarantee.

## URL resolution

Every protocol handler resolves URLs via `pkg/urlswap.Resolve(provider, defaults, reqHost)`:

1. If the admin set `ExternalURLs.IssuerURL` / `PortalURL` / `ConsoleURL` in settings, those win.
2. Else fall back to `bootstrap.Config.Server.{IssuerURL,PortalURL,ConsoleURL}`.
3. If the resolved host is `localhost` / `127.0.0.1` AND the inbound request hit a different host (LAN IP, override domain), the host is swapped to the inbound host (port preserved).

This means dev / LAN testing works without admin intervention, while prod canonical URLs are honored verbatim.

## SPA architecture

`web/packages/shared` is the cross-app library:

- `api/` — axios clients per domain (one file per resource).
- `i18n/` — i18next + 16 namespace bundle in `locales/{zh-CN,en-US}.ts`.
- `hooks/` — React hooks (`useAuthStore`, `useBootstrap`, `useTranslation` re-export).
- `ui/` — `Toaster`, `IconPicker`, `AppIcon`.
- `utils/` — `cn`, `formatDate` (locale + tz aware), `statusLabel` (i18n-aware), `parseUserAgent`.

Each SPA imports from `@mxid/shared/...` paths. Tailwind v4 needs an `@source` directive in each app's `index.css` to scan shared package files; without it, classes used only in `Toaster` etc. are tree-shaken out.

## Multi-tenancy model

- One PostgreSQL table per resource is partitioned by `tenant_id`.
- The default tenant (`id=1`) is created on first migration.
- Apps may be `scope=tenant` (visible only to that tenant) or `scope=shared` (visible to all tenants).
- Protocols infer the tenant from session, or from a `?tenant=<code>` query parameter on the portal login URL.

## Logout — global session teardown

Logout is a cross-surface operation. A single logout request (from console, portal, or a protocol `end_session` / SLO endpoint) destroys **all** sessions held by the user:

1. Console admin session (Redis key)
2. Portal end-user session (Redis key)
3. Any active protocol tickets (OIDC refresh tokens, CAS ticket-granting tickets, SAML assertions in flight)

This achieves true single sign-out: after logout, the user cannot resume any surface without re-authenticating, regardless of which surface triggered the logout. When logout runs through a protocol `end_session` / SLO endpoint, back-channel SLO notifications to the relevant SPs (OIDC Back-Channel Logout, SAML SLO) are dispatched as well.

## Extending — add a new external IdP

1. Implement the `externalidp/providers.Provider` interface.
2. Register the provider type in `internal/domain/externalidp/providers/init.go`.
3. Add UI: the IdP CRUD page (`web/apps/console/src/pages/idps`) will pick up the new `type` from the API automatically; add an icon + label only if you want them branded.

## Extending — add a new protocol

1. New package under `internal/protocol/<name>/`.
2. Implement handler, route registration, and ticket / token store as needed.
3. Add `<name>.Register(...)` call in `app/run.go`, alongside CAS / SAML / OIDC.
4. Add a row to `app.Protocol` constants + `ProtocolDefaults` setting + UI dropdown.

## Editions & licensing (CE / EE)

Open-core, single source of truth, no fork. The server entrypoint lives in the
importable package `github.com/imkerbos/mxid/app` (`app.Run()`); `cmd/server` is
a thin `main` that calls it. The EE distribution (`github.com/imkerbos/mxid-ee`,
private) is its own module that imports `app`, blank-imports its feature
packages, and runs the same `app.Run()`.

- **`pkg/ee/license`** — verifies an Ed25519-signed token against an embedded
  public key (the private key lives only in the `license-authority` repo). Holds
  the process-wide `Current()` Manager; CE by default, EE when a valid license is
  loaded from the License setting (DB-persisted, console-activated, hot-reloaded).
  Offline + product-bound; expiry reverts to CE limits with existing data
  grandfathered.
- **`pkg/ee/registry`** — the extension seam. EE feature packages call
  `registry.RegisterConsole(...)` from `init()`; `app.Run` invokes the registered
  mounters. CE imports none, so EE code is *absent* from the CE binary.
- **Two gating tiers**:
  - *Runtime-gated* (`middleware.RequireFeature` → `license.Current().Has(feature)`):
    `multi_tenant`, `branding`, `conditional_access`. The code and DB schema ship
    in the CE binary (the schema is foundational / grandfathered); the capability
    is locked behind a license check at the HTTP layer and unlocked when a valid
    EE license is present.
  - *Code-separated*: `external_idp`, `webauthn`, `scim`, `advanced_stepup`, `sms`
    and other high-value features exist **only** in the private `mxid-ee` module
    and in `garble`-obfuscated EE images. They are registered at startup via
    `pkg/ee/registry` (`RegisterConsole` for route mounting, `RegisterInit` /
    `InitContext` for the DI seam). The CE binary contains none of their code;
    their routes return 404 on CE.
- **Feature advertisement** (`/api/v1/system/info`): the endpoint reports only
  the features actually registered in the running binary. CE binaries do not list
  `external_idp` (its package is absent; the route does not exist). EE binaries
  list it only after the package has been blank-imported and its `init()` has
  called `registry.Register*`. This prevents clients from relying on a feature
  that the current binary cannot serve.

User-facing matrix, activation, and limits: [EDITIONS.md](EDITIONS.md).

## Offboarding & durable delivery

Revoking a departing user's access is tiered by how much MXID controls the
target (`internal/domain/offboarding`):

- **L1 — SSO cut (CE).** One admin action disables the account (which also makes
  the OIDC refresh grant reject the user) and kills every session across the
  console / portal / protocol namespaces, then back-channel-logs-out the apps the
  user is signed into. This revokes access to every app reached through MXID SSO,
  with no downstream credentials.
- **L3 — review checklist (CE).** Records the user's app footprint as a console
  review panel so an admin can confirm cleanup for apps that also hold local
  accounts, and (optionally) fires a signed webhook to the customer's IT/HR/ITSM
  system.
- **L2 — downstream deprovision (EE).** For an app with provisioning enabled, an
  EE-only SCIM 2.0 connector (`mxid-ee/features/scim`, license-gated `scim`)
  deactivates the downstream account (`PATCH active=false`). The per-app config
  schema is CE; only the connector is EE.

Side effects that must survive a crash (the offboarding webhook, the SCIM
deprovision) ride a **transactional outbox** (`internal/outbox`,
`mxid_outbox`): producers `EnqueueTx` in the same DB transaction as the state
change, and a worker claims due rows with `FOR UPDATE SKIP LOCKED` (replica-safe,
no leader election), dispatches by kind, and backs off / dead-letters on failure.
The in-memory event bus is at-most-once, so security actions never ride it.

## Things deliberately not done (yet)

- **Federation across MXID instances.** Single-instance only.
- **WebAuthn / FIDO2** — only TOTP for MFA today.
- **SCIM inbound provisioning** — MXID is not yet a SCIM *service provider* (no
  inbound create/update of MXID users via SCIM). Outbound SCIM 2.0
  *deprovisioning* exists for offboarding (L2, EE) — see below.
- **DPoP / OAuth 2.1 strict mode** — token endpoint stays on Bearer.
- **JIT user provisioning from external IdP** — exists per-IdP but not configurable through UI.

These are all candidate features for future versions.
