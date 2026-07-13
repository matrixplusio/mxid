# Form-Fill SSO (SWA) — Design

Status: **EVALUATED / scope locked, not yet scheduled**. Companion to the shipped
**Link (bookmark) app** (protocol `link`), which gives internal web-only systems
a portal tile but no credential automation. This doc specifies the next tier:
**Secure Web Authentication (SWA) / form-fill SSO** — MXID stores each user's
downstream username+password and a browser extension auto-submits the target
site's login form, so the user signs into MXID once and launches without
re-typing.

Benchmarks: Okta SWA, OneLogin Form-Based Apps, LastPass/1Password SSO apps.

**Locked decisions (2026-07-13 review):**
- **Build B1 + B2** — full form-fill incl. the browser extension. Vault-only was
  rejected as near-worthless (it degenerates to a weak password manager).
- **Target scale: <10 internal systems, stable login pages.** This is what makes
  the extension's form-rule maintenance survivable. If the fleet grows or churns,
  revisit — the maintenance tail is the risk, not the build.
- **EE-gated** — form-fill is a credential-custodian feature; it ships as an EE
  feature (`form_fill`), code-separated into the private `mxid-ee` repo, absent
  from the CE binary. See §9.
- **Rule authoring = capture mode** — the extension records a real login once and
  auto-generates selectors. Admin-hand-written CSS selectors are a fallback, not
  the primary path. This is the difference between viable and unviable at scale.

> **Design stance:** form-fill is the *last-resort* integration for systems that
> genuinely cannot speak OIDC/SAML/CAS. It is inherently fragile (login forms
> change) and turns MXID into a downstream-password custodian (a honeypot). Where
> a downstream system *can* be changed, route it to OIDC instead. Okta itself
> markets SWA as a fallback, not the primary path.

---

## 1. Scope & non-goals

In scope:
- Per-app credential vault (username + password, encrypted at rest) in **two
  coexisting modes** — set per app via `credential_mode` (see §2.1):
  - **`per_user`** (default) — each user stores their own downstream credential.
  - **`shared`** — an admin stores one credential that all authorized users launch
    with (a shared/service account). Mirrors Okta SWA's "administrator sets
    username and password" scheme.
- Admin app config: mark an app `protocol = form`, pick the credential mode,
  describe its login form.
- End-user portal screen to store/update/delete their own credentials (per_user
  mode); read-only for shared mode.
- Browser extension that fills + submits the login form on launch.
- Step-up MFA + full audit on every credential reveal (both modes).

Non-goals (v1):
- Password *rotation* into downstream systems (that's provisioning/SCIM, separate).
- Per-group credential targeting (shared is app-wide in v1, gated by the app's
  access policy — not a distinct credential per group).
- Mobile app auto-fill (extension is desktop browser only).
- Headless/proxy injection (rejected — see §4, option B).

---

## 2. Data model

Reuse the existing `mxid_app_account` table (already AES-256-GCM encrypted via
`crypto.Secret`) — it currently stores `account` + `credential` per (app, user).
It is the natural vault row. Extend, don't invent:

```
mxid_app_account (existing — per_user rows)
  id, app_id, user_id, tenant_id
  account     VARCHAR(256)   -- downstream username (plaintext; not a secret)
  credential  crypto.Secret  -- downstream password, AES-256-GCM at rest, masked in JSON
  created_at, updated_at
  UNIQUE(app_id, user_id)            -- ALREADY EXISTS (000004)
  FK user_id -> mxid_user(id)        -- ALREADY EXISTS (000058), NOT NULL, ON DELETE CASCADE
  + last_used_at TIMESTAMPTZ NULL    -- NEW (migration): stale detection
```

### 2.1 Credential modes — two tables, not a sentinel

The `credential_mode` on the app selects where the credential lives. **A sentinel
`user_id=0` in `mxid_app_account` was rejected**: that column carries a NOT-NULL
FK to `mxid_user(id)` (000058), so a fake user_id would violate the FK. Instead:

- **`per_user`** — rows in existing `mxid_app_account`, one per real user
  `(app_id, user_id)`. User owns and writes. FK + UNIQUE already there.
- **`shared`** — a **new app-level table** `mxid_app_shared_credential`, one row
  per app, owned/written by an admin, revealed to every authorized user:

```
mxid_app_shared_credential (NEW)
  app_id      BIGINT PRIMARY KEY REFERENCES mxid_app(id) ON DELETE CASCADE
  account     VARCHAR(256)  NOT NULL     -- shared/service-account username
  credential  crypto.Secret (VARCHAR 512) -- shared password, AES-256-GCM at rest
  last_used_at TIMESTAMPTZ NULL
  created_at, updated_at
  created_by  BIGINT NULL                -- admin who set it (audit)
```

Reveal resolution:
```
mode == per_user  -> mxid_app_account         WHERE app_id=? AND user_id=<session user>
mode == shared    -> mxid_app_shared_credential WHERE app_id=?   (any authorized user)
```

App-level table is also conceptually cleaner: a shared credential is a property of
the app, not of a user. **Password never goes in `protocol_config`** (that JSONB is
plaintext at rest) — both tables use `crypto.Secret`.

### 2.2 App-level form descriptor

Lives in `mxid_app.protocol_config` (JSONB, already present), no new column:

```jsonc
// protocol_config for a `form` app
{
  "credential_mode":  "per_user",                      // "per_user" | "shared"
  "login_url":        "https://wiki.internal/login",   // where the form lives
  "username_selector": "#username",                    // CSS selector
  "password_selector": "#password",
  "submit_selector":   "button[type=submit]",
  "extra_fields":     [{"selector":"#tenant","value":"acme"}], // optional static fields
  "success_url_glob": "https://wiki.internal/dashboard*"        // optional, to confirm login
}
```

`ProtocolLink` (bookmark) stays a distinct protocol; `form` is additive. Add
`form` to: `dto.go` oneof, `validProtocol`, portal launch (returns a signal, not
a URL — see §5), console protocol dropdown, and the badge maps.

---

## 3. Threat model (this is the expensive part — do it first)

The vault holds **plaintext-recoverable downstream passwords for every user**.
In the OIDC/SAML/CAS model MXID never holds a downstream password; here it does.
Compromise blast radius = every stored credential for every affected system.

| Threat | Control |
|---|---|
| DB dump leaks credentials | AES-256-GCM at rest via `crypto.Secret`; KEK in `MXID_CRYPTO_KEY_ENCRYPTION_KEY` only (env, never committed); `leakedDevKEKs` blacklist enforced in release. |
| KEK leak → mass decrypt | KEK rotation runbook; add any exposed KEK to `leakedDevKEKs`; consider per-tenant DEK derived via `MasterKey.Derive`. |
| Compromised MXID session pulls all my creds | **Reveal requires step-up MFA** (reuse sudo window). Decrypt endpoint is sudo-gated, short TTL. |
| Malicious admin reads user creds | Admins can configure the *form* but the **decrypt path is user-scoped only** — no admin API returns another user's plaintext. Enforce at the query (user_id from session, never from request). |
| Credential exfil via API | Plaintext is returned **only** to the extension, over the authenticated session, one app at a time, rate-limited; never bulk. `crypto.Secret` masks in every normal JSON path. |
| Plaintext in logs | `crypto.Secret` already masks in JSON/logs — keep it; never log `.Reveal()` output; audit records the *event*, not the value. |
| Phishing extension / rogue content-script | Extension only injects into the app's configured `login_url` origin; MXID API is CORS-locked to the extension ID; creds fetched over the user's authenticated MXID session, not a long-lived token. |
| Replay / stale creds | `last_used_at` + optional downstream login-failure signal surfaces rot. |
| Audit gap | Every store/update/delete/reveal emits an audit record (who/ip/when/app/result) via existing `auditctx`. Reveal is the highest-signal event. |

**Gate:** B does not start until this threat model is signed off. The reveal API
must be sudo-gated + user-scoped + audited from commit one — retrofitting is how
honeypots leak.

---

## 4. Delivery mechanism — decision

Three ways to actually log the user in; only one survives:

| Option | Verdict | Why |
|---|---|---|
| **A. Browser extension (MV3)** | **CHOSEN** | Handles CSRF tokens, JS logins, SameSite cookies — the browser *is* the client, so the session is real. Cost: greenfield, cross-browser upkeep, per-app form rules that break on site redesign. |
| B. Reverse proxy / header injection | Rejected | Breaks on CSRF tokens, JS-rendered logins, MFA; puts MXID in the data path (latency, TLS, availability); only works on trivial forms. |
| C. Auto-submit cross-origin POST from portal | Rejected | Blocked by CSRF tokens + SameSite=Lax/Strict cookies; brittle; effectively non-functional on modern apps. |

The extension is a **separate deliverable** (own repo/build/publish + enterprise
managed-install via GPO/MDM). Do not couple its release train to the MXID
server sprint.

---

## 5. Launch flow (form app)

Unlike SSO protocols, the server can't hand back a redirect URL. `GetAppLaunchURL`
for a `form` app returns a structured signal the portal/extension understands:

1. Portal launch → server returns `{ "kind": "form", "app_id": ..., "login_url": ... }`
   (extend the launch contract; today it's a bare `launch_url` string).
2. Portal opens `login_url` in a new tab.
3. Extension content-script detects the tab origin matches a `form` app it knows,
   calls MXID `GET /portal/apps/{id}/credential` (session-auth, **sudo-gated**),
   receives `{ account, credential }` once.
4. Extension fills `username_selector`/`password_selector`/`extra_fields`, clicks
   `submit_selector`.
5. Optional: confirm navigation reached `success_url_glob`; stamp `last_used_at`.

If the extension is absent, the portal degrades to Link behavior (opens
`login_url`; user types manually) — so a `form` app is never worse than a
bookmark.

### 5.1 Capture mode (rule authoring — LOCKED as primary)

Hand-writing CSS selectors per app does not scale past a handful of sites. The
extension ships a **capture mode**:

1. Admin (or first user) clicks "record login" for a `form` app in the portal.
2. Extension enters capture on the app's `login_url`, watches the user perform one
   real login, and records: the field the user typed the username into, the field
   they typed the password into, the element they clicked to submit, and the URL
   they landed on (→ `success_url_glob`).
3. Extension proposes a form descriptor (the §2 JSONB); admin confirms → saved to
   `protocol_config`.
4. Subsequent launches replay it.

Manual selector entry in console stays as a fallback for headless/locked-down
setups, but capture is the path users see. Capture generation lives in the
extension (B2); the descriptor it emits is stored via the same admin config API
as manual entry, so B1b's backend is authoring-method-agnostic.

---

## 6. Phasing & effort

All server/portal logic (B0–B1) lands in the **`mxid-ee` repo** as the `form_fill`
feature (see §9). The extension (B2–B3) is its own repo.

| Phase | Deliverable | Effort | Blocks on |
|---|---|---|---|
| **B0** | Threat model sign-off (§3), reveal-API security spec | 1–2 days | — |
| **B1a** | Vault backend (mxid-ee): reveal seam + `form_fill` feature registration, extend `mxid_app_account` (unique + last_used_at), user-scoped store/update/delete, **sudo-gated user-scoped reveal**, audit on all, EE license gate | 4–5 days | B0 |
| **B1b** | Admin `form` app config API (authoring-method-agnostic descriptor) + `form` wired into dto/validProtocol/launch signal/badges + CE↔EE seam for the protocol enum | 2–3 days | B1a |
| **B1c** | Portal "My credentials" screen (model on `profile/index.tsx`) + "record login" entry point, toast feedback | 2–3 days | B1a |
| **B2** | Browser extension MV3 MVP (Chrome): **capture mode** (record→generate descriptor) + content-script fill+submit + CORS-locked sudo-gated credential fetch | 4–6 weeks | B1a/b |
| **B3** | Extension hardening: cross-browser (Edge/Firefox), managed-install packaging (GPO/MDM), breakage telemetry + re-capture prompt | ongoing | B2 |

B0–B1 (server + portal, in mxid-ee) is ~2 weeks. It is a prerequisite but delivers
little user value alone (creds stored, revealed to the user manually) — the payoff
needs B2. B2 is bigger than the earlier estimate because capture mode is now in
scope (it was the "big usability win, more build" option), but capture is what
keeps a <10-site fleet maintainable. B2/B3 is the long pole + maintenance tail —
own repo, own release train.

---

## 7. Decisions & remaining open questions

Resolved in the 2026-07-13 review:
- **Build scope:** B1 + B2 (full form-fill incl. extension). ✔
- **EE gating:** yes — `form_fill` EE feature, code-separated (§9). ✔
- **Rule authoring:** capture mode primary, manual selectors fallback (§5.1). ✔
- **Target fleet:** <10 stable sites — the assumption that makes maintenance viable. ✔

Still open (design-time, not blocking the go/no-go):
1. **Per-app DEK vs single KEK.** RESOLVED → **single process KEK** (reuse
   `crypto.Secret` as-is). Grounding check killed the "per-app DEK" lean:
   `crypto.Secret` encrypts via the process-wide key set by
   `crypto.SetSecretMasterKey`, and `MasterKey.Derive(label) [32]byte` returns raw
   key material with no `Encrypt` method — a per-app DEK means bypassing
   `crypto.Secret` entirely and hand-rolling `EncryptAES256GCM`/`Decrypt` per
   call-site, losing the transparent driver.Valuer + JSON masking. For a <10-app
   fleet that's a bad trade. `mxid_app_account.credential` already uses the single
   KEK via `crypto.Secret` — keep it. Revisit per-app DEK only if the threat model
   escalates.
2. **Extension distribution:** Chrome Web Store (public listing) vs enterprise
   private/pinned hosting. Enterprise buyers will want managed installs (GPO/MDM);
   likely need both.
3. **Where the vault row lives CE vs EE:** `mxid_app_account` already exists in CE
   schema (foundational, grandfathered). Decide whether the *schema* stays CE
   (like branding's foundational schema) while all *logic* (reveal, form
   descriptor, capture API) lives EE-only. Recommended: schema + `link`/`form`
   enum foundational in CE; everything behind the credential is EE. Resolve in B0.
4. **Capture-mode trust:** capture runs in the user's browser on the real login
   page — ensure the recorded descriptor can't be poisoned to exfiltrate to a
   third origin (validate selectors resolve within `login_url` origin only).

---

## 9. EE placement (code separation)

Per the CE/EE split (see root `CLAUDE.md`), high-value features live ONLY in the
private `mxid-ee` repo, garble-obfuscated, absent from the CE binary. Form-fill is
a credential custodian → **code separation**, not just runtime gating.

- **New EE feature key:** `form_fill` (join `external_idp`, `webauthn`, `scim`, …).
- **Registration:** via `pkg/ee/registry` — a fuller feature through the
  `RegisterInit` / `InitContext` DI seam (it needs services + routes, not just one
  console route). Portal + console routes registered through the EE seam.
- **Gate:** `internal/middleware.RequireFeature(license.FeatureFormFill)` (new key;
  `RequireFeature` is at `internal/middleware/feature.go:18`) guards every
  form-fill route; expiry → graceful downgrade (existing stored creds keep working
  / revealing, no NEW form apps past the gate — mirror the standard EE expiry
  policy). Add `FeatureFormFill` to `pkg/ee/license/features.go` (that file is in
  the CE binary — the KEY is CE-side, the CODE is EE-side) and to
  `ImplementedFeatures` once shipped.
- **CE seam (foundational, stays in CE):** the `form` protocol enum value + the
  `mxid_app_account` schema + the launch-contract shape. These are cheap, schema-
  level, and grandfathered — same pattern as branding/conditional-access schema
  living in CE while the capability is EE-gated. The *logic* behind them (vault
  CRUD, sudo-gated reveal, form descriptor authoring, capture API) is EE-only.
- **Reuse:** the reveal endpoint gates on the **CE base step-up seam** —
  `authn.StepUpMiddleware` / `stepUp.Fresh(c, tenantID)` at
  `internal/domain/authn/stepup.go` (default window 1800s /
  `internal/domain/setting/service.go:360`). This lives in CE and is what JIT
  approval already uses (`internal/domain/access/handler.go:234`). It is NOT the
  `advanced_stepup` EE feature (which is declared in `features.go` but currently
  absent from `ImplementedFeatures`) — do not couple form-fill to an unimplemented
  feature.
- **Extension:** separate repo entirely (not Go, not garble). Talks to the EE
  routes over the authenticated session. Its own build/publish/release train.

---

## 8. Reused primitives (already in the codebase)

- `pkg/crypto` `Secret` (driver.Valuer/Scanner, masks in JSON) + `MasterKey.Encrypt/Decrypt/Derive`.
- `mxid_app_account` table with `credential crypto.Secret`.
- Sudo / step-up MFA window (portal + console consistent) — gate the reveal API.
- `auditctx` who/ip/when/what/result — audit store + reveal.
- `leakedDevKEKs` blacklist + `validateSecrets` release gate.
- Portal per-user settings pattern (`profile/index.tsx`) — model the credentials screen.
```
