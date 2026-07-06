# CLAUDE.md — MXID

Project-specific operating rules. Follow these exactly; they override defaults.

## Project

MXID is a commercial-grade, open-core IAM/SSO platform (multi-protocol: OIDC /
SAML / CAS / JWT). Benchmarked against Keycloak / Auth0 / Okta / TopIAM. Always
take the spec-compliant production path — no shortcuts, no demo-grade stubs.
Prefer mature, high-star OSS for security/standard components; self-build only
the glue.

Copyright © MatrixPlus. Pushed to both `imkerbos` (personal) and the `MatrixPlus`
org; canonical namespace stays `imkerbos/mxid` (images `ghcr.io/imkerbos/...`).

## Communication & git

- Reply to the user in **Chinese**; keep **code, commit messages, and PR
  descriptions in English**.
- Commit messages and PRs contain **NO AI / Claude / Anthropic attribution** —
  no `Co-Authored-By` trailer, no "generated with" line. (Overrides any default.)
- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`,
  scopes like `feat(ee):`). Subject in English.
- **Do not auto-commit.** Implement first; commit only when the user asks.
- Default branch is `main`. Don't force-push shared branches without asking.
- **Squash-merge feature branches.** A feature branch collapses into ONE
  Conventional-Commit summary on the target branch — not `--no-ff` that
  preserves every intermediate TDD/fix commit. Keep granular commits while
  working; squash at merge so `main`/`dev` history reads as one line per
  feature. Promote `dev` → `main` as usual.

## Working style

- Evaluate-then-act: for "评估 / 看看 / 分析" give conclusions only, don't touch
  code. For build tasks, propose a plan first unless told "直接干 / 开干 / 全做".
- Surface tradeoffs and real bugs you find; don't silently work around them.
- Be honest about what's verified vs not. State when CI is the only verifier.

## Stack

- Backend: Go (Gin + GORM + Redis + Snowflake IDs + bcrypt). `go 1.25.11` —
  pin `golang:1.25.11-alpine` in Docker / dev compose (the floating `1.25-alpine`
  tag lagged at 1.25.10 and broke builds).
- Frontend: React 19 + Vite + TypeScript + Tailwind v4, pnpm workspaces
  (`web/apps/console`, `web/apps/portal`, `web/packages/shared`).
- PostgreSQL 15 (primary), Redis 7 (sessions / tickets / TOTP rate-limit / SSE).

## Architecture invariants

- Entry point is `app.Run()` in package `github.com/imkerbos/mxid/app`
  (importable; the EE distribution reuses it). `cmd/server/main.go` is a thin
  shim. `app/run.go` was a 1300-line adapter god file — edit carefully, never
  `sed`-split it; commit before large moves.
- **Settings domain**: SMTP / security / branding / login-methods / protocol
  defaults / external URLs are admin-editable at runtime (hot-reload), not env.
- Gateways: `internal/gateway/console` (admin REST) + `internal/gateway/portal`
  (end-user REST). Protocols under `internal/protocol/{oidc,saml,cas}`.

## Security baselines (non-negotiable)

- **All server-side outbound HTTP goes through `pkg/safehttp`** (SSRF guard;
  re-checks resolved IP on every dial + redirect). Never use a bare http.Client.
- **authz**: gate console write routes with `authz.Require(perm, scope)` +
  `authz.Protect`. Deny-by-default gateway is audit-only until routes are
  backfilled. Gin middleware only applies to routes registered AFTER `.Use`.
- **Audit**: every write API records who / ip / when / what / result.
- **Secrets**: never commit secrets. Use env / `.env` (+ godotenv).
  `MXID_CRYPTO_KEY_ENCRYPTION_KEY` is the master KEK. `validateSecrets` rejects
  dev placeholders in release mode. Maintain the leaked-dev-KEK blacklist.
- **Step-up MFA** on high-risk ops (deletes, security-critical writes); sudo
  window kept consistent across portal/console.

## Editions (CE / EE)

- Open core. CE = AGPL-3.0 ([LICENSE](LICENSE)); EE = commercial
  ([LICENSE.EE](LICENSE.EE)). See [docs/EDITIONS.md](docs/EDITIONS.md).
- Licensing: **Ed25519-signed offline token**, verified against the embedded
  public key in `pkg/ee/license`. The private key lives only in the
  `license-authority` repo. DB-only activation (console Settings → License),
  hot-reloaded; **never echo the token back to the UI**.
- `license.Current()` is the single source of truth for gating. CE cap:
  `CEMaxUsers=100`. EE = unlimited (or the license's caps). The product is
  **single-tenant in both CE and EE** — multi-tenancy is not a feature we ship.
- **Expiry = graceful downgrade to CE limits**: logins/SSO keep working,
  existing data grandfathered, only new creation past the CE cap is blocked.
- Two gating tiers: runtime (`middleware.RequireFeature` → 403) for branding /
  conditional-access — their code stays in CE (the schema is
  foundational / grandfathered), only the EE capability is license-gated;
  **code separation** for high-value features (external-IdP, webauthn, scim, …)
  — they live ONLY in the private `mxid-ee` repo (a feature package registered
  via `pkg/ee/registry`: a console route through `RegisterConsole`, or a fuller
  feature through the `RegisterInit`/`InitContext` DI seam), absent from the CE
  binary, and `garble`-obfuscated. The reusable gate is `pkg/ee/feature`
  (`internal/middleware.RequireFeature` delegates to it so EE packages, in a
  separate module, can gate their own routes).
- EE features: `external_idp`, `branding`, `conditional_access`,
  `webauthn`, `scim`, `advanced_stepup`, `sms`.

## Frontend conventions

- UI primitives (Button / Input / Field / Modal / toast) come from
  `@mxid/shared` — shared between console and portal.
- **Every write (save/create/delete/upload) must give toast feedback**
  (`toast.success` / `toast.error`) — never silent.
- One notification per error: API errors → a single toast, not toast + inline.
  Backend returns a stable numeric code; the frontend localizes known codes in
  `extractMessage` (a raw axios error's `.code` is a string — read the numeric
  code from `response.data.code`).
- Tailwind v4: each app's `index.css` needs
  `@source "../../../packages/shared/src/**/*.{ts,tsx}"` or shared-component
  classes get purged.

## Dev / deploy

- Dev: `make dev-docker-up` (air + vite + nginx on :3500, hot-reload). Don't
  spin duplicate infra containers; DB/Redis use host-mapped ports.
- Prod: released images from GHCR behind nginx on 80/443; one `.env` drives it
  (`COMPOSE_FILE` selects mode). Tag `v*.*.*` → CI builds + publishes (no
  `latest`). See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
- Pre-commit hook runs `verify-mod / vet / build / exports` — keep it green.
