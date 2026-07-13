# Form-Fill SSO — B0 Security Spec & Seam Decisions

Prerequisite gate for B1. **No B1 code lands until this is signed off.** Companion
to [FORM-FILL-SSO-DESIGN.md](FORM-FILL-SSO-DESIGN.md); this doc pins the security
contract and the CE/EE seams to *concrete existing primitives* (file:line), so B1
is unambiguous and reuses the platform instead of inventing parallel mechanisms.

All seam references verified against the tree on 2026-07-13. Re-verify names
before coding — the repo moves.

---

## 1. Why this gate exists

The form-fill vault holds **plaintext-recoverable downstream passwords for every
user**. Every other MXID protocol (OIDC/SAML/CAS) is credential-*less* on the MXID
side. This feature inverts that. A DB dump or a hijacked session must not become a
mass credential leak. The controls below are non-negotiable and must be present in
the *first* B1 commit — retrofitting security onto a shipped vault is how
honeypots leak.

---

## 2. Data at rest

**Decision: reuse `crypto.Secret` with the single process KEK.** No per-app DEK
(see design §7.1 — per-app derivation would bypass `crypto.Secret` and lose
transparent masking, a bad trade for a <10-app fleet).

- **per_user**: existing `mxid_app_account` (already `credential crypto.Secret`,
  AES-256-GCM at rest via `pkg/crypto/secret.go:108` Valuer / `:125` Scanner,
  masked `"********"` in JSON). `UNIQUE(app_id, user_id)` + FK already exist
  (000004 / 000058); migration only adds `last_used_at TIMESTAMPTZ NULL`.
- **shared**: new `mxid_app_shared_credential` table (design §2.1) — app-level,
  one row per app, `credential crypto.Secret`. Sentinel `user_id=0` in
  `mxid_app_account` was rejected (NOT-NULL FK to `mxid_user`).
- Verified: `mxid_app_account` currently holds **0 rows**, so the migration is
  non-breaking.
- KEK: `MXID_CRYPTO_KEY_ENCRYPTION_KEY`, wired at boot via
  `crypto.SetSecretMasterKey` (`internal/bootstrap/app.go`). `validateSecrets`
  release gate + `leakedDevKEKs` blacklist already enforce KEK hygiene — no new
  key management.
- **Never** log `Secret.Reveal()` output. Audit records the *event*, not the value.

---

## 3. Reveal API — the critical path

The one endpoint that turns ciphertext into a usable password. Spec:

```
GET /portal/apps/{id}/credential      (EE-only route; 404 in CE)
```

Mandatory controls (ALL required, enforced server-side):

1. **Authenticated session** — standard portal auth middleware
   (`internal/domain/authn/middleware.go` stamps the actor via `auditctx.With`).
2. **Sudo / step-up gate** — call `stepUp.Fresh(c, tenantID)` inline, exactly as
   JIT approval does (`internal/domain/access/handler.go:234`), against the CE
   base seam `internal/domain/authn/stepup.go`. Not fresh → 401/challenge, never
   the credential. Window default 1800s (`internal/domain/setting/service.go:360`).
   **NOT** the unimplemented `advanced_stepup` EE feature.
3. **Scope resolved by `credential_mode`, never by request-supplied id** (see
   design §2.1):
   - `per_user` → `WHERE app_id=? AND user_id=<session.UserID>`. There is **no**
     admin/API path that returns another user's per_user plaintext.
   - `shared` → `mxid_app_shared_credential WHERE app_id=?`, but only after the
     caller passes the app's **access policy** (they must be authorized to launch
     the app). The shared secret is deliberately visible to all authorized users —
     that is the mode's definition — but still sudo-gated + audited per reveal.
   The mode is read from the app's `protocol_config`, server-side. The client
   never chooses the mode or the target user_id.
4. **One app at a time** — no bulk/list endpoint that returns plaintext. Reveal is
   single-app per call.
5. **Rate-limited** — reuse the existing per-user limiter pattern; a tight cap
   (e.g. N reveals/min) — bulk reveal is an exfil signal.
6. **Audited** — every reveal emits a domain event via `event.Bus.Publish`
   (`pkg/event/bus.go:44`), actor already stamped by `auditctx`. This is the
   highest-signal audit event in the feature. Store/update/delete audited too.
7. **CORS-locked** — the only cross-origin caller is the browser extension; lock
   the reveal route's CORS to the published extension origin/ID, not `*`.

Response is the plaintext once, over TLS, to the extension. `crypto.Secret` masks
it on every *other* JSON path by default, so only this deliberately-unmasked
endpoint exposes it.

---

## 4. Write paths (store / update / delete)

**`per_user` mode — end user writes their own (portal, EE route):**
```
PUT    /portal/apps/{id}/credential    { account, credential }
DELETE /portal/apps/{id}/credential
```
- Scoped to session `user_id`, never request. Writes/removes that user's own row.
- No step-up to *store* (you're giving your own password); step-up is for *reveal*.

**`shared` mode — admin writes the one shared row (console, EE route):**
```
PUT    /console/apps/{id}/shared-credential   { account, credential }
DELETE /console/apps/{id}/shared-credential
```
- Admin-only (console EE route, `authz.Require` + `RequireFeature`). Writes the
  `user_id=0` sentinel row. End users have **no** write path in shared mode.
- Setting a shared credential is itself a **high-risk write → step-up gated** and
  audited (an admin planting a service-account password).

Common to both: `credential` bound as a masked field, encrypted at rest by
`crypto.Secret`; every store/update/delete audited. Reuse the existing
`AppAccountRequest` DTO shape (CE, `dto.go:113`) where it fits; handlers are EE-only.

---

## 5. CE / EE seam — concrete split

Per root `CLAUDE.md`: high-value features are code-separated into the private
`mxid-ee` module, garble-obfuscated, absent from the CE binary.

**Stays in CE (foundational schema/enum — grandfathered, like branding schema):**
- `app.ProtocolLink` already shipped; add `app.ProtocolForm = "form"` enum +
  dto `oneof` + `validProtocol` + launch-signal shape + protocol badge.
- `mxid_app_account` `last_used_at` column + the new `mxid_app_shared_credential`
  table (both plain schema, foundational).
- `license.FeatureFormFill` **key** in `pkg/ee/license/features.go` (that file is
  compiled into CE for license verification; the key is CE, the logic is EE).

**EE-only (`mxid-ee` module, `form_fill` feature):**
- Vault service: store/update/delete/reveal, mode-aware (per_user vs shared, §3/§4),
  all audited.
- Sudo-gated reveal handler (§3).
- Admin form-descriptor config API (authoring-method-agnostic — accepts a
  descriptor whether hand-written or capture-generated) + `credential_mode` select.
- Admin shared-credential write route (console, step-up gated, §4).
- Portal "my credentials" + "record login" routes (per_user mode).

**Registration** (both verified in `pkg/ee/registry`):
- `RegisterInit(Initializer)` — `Initializer = func(*InitContext) error`
  (`seam.go:109`). `InitContext` (`seam.go:91-106`) carries `App`, `SessionMgr`,
  `ConsoleGate`, `ExternalURLs`, `OutboxRegister`, etc. Wire vault services +
  portal routes here.
- `RegisterConsole(ConsoleMounter)` — `ConsoleMounter = func(rg *gin.RouterGroup)`
  (`registry.go:14`) for the admin form-config routes.
- Model on the existing `external_idp` EE feature (closest analogue: has both
  portal + console surface). CE binary keeps registry empty → routes 404,
  feature absent from `/system/info` discovery (`registry.go:50-56`).
- Every EE route wrapped in `middleware.RequireFeature(license.FeatureFormFill)`
  (`internal/middleware/feature.go:18`). Expiry → graceful downgrade: stored creds
  keep revealing, no NEW form apps past the gate.

---

## 6. Capture-mode trust boundary

Capture runs in the user's browser on the real login page (design §5.1). Risk: a
poisoned descriptor exfiltrating the password to a third origin on replay.

Controls:
- Recorded selectors must resolve **within the app's `login_url` origin** only;
  the extension refuses to fill fields on any other origin.
- The fill step posts credentials only to the page's own form action, never to an
  arbitrary URL from the descriptor.
- Admin confirms the capture-generated descriptor before it's saved (human in the
  loop on the origin/selectors).

---

## 7. Audit events (new)

| Event | When | Severity |
|---|---|---|
| `app.credential.stored` | user saves/updates their per_user credential | info |
| `app.credential.deleted` | user removes their per_user credential | info |
| `app.credential.shared_set` | admin sets/updates the shared credential | **high** |
| `app.credential.revealed` | reveal returns plaintext to extension (mode + target in payload) | **high** |
| `app.credential.reveal_denied` | reveal blocked (no step-up / not authorized / rate-limited) | **high** |

All stamped with `auditctx` actor (who/ip/session). For **shared** reveals the
actor is the real user who launched — so a shared service account still has
per-use accountability (who used it, when). Reveal events are the
security-monitoring anchor.

---

## 8. B0 sign-off checklist

B1 may start only when all are ✔:

- [ ] Threat model (design §3 + this doc) reviewed and accepted.
- [ ] **Credential modes** (§2.1, per_user + shared coexisting) accepted; sentinel
      `user_id=0` for the shared row confirmed.
- [ ] Reveal API contract (§3) approved — mode-based scoping, sudo gate, no-bulk,
      rate-limit, CORS-lock, audit all confirmed as hard requirements.
- [ ] CE/EE split (§5) confirmed: `ProtocolForm` + schema + feature key in CE;
      all credential logic in `mxid-ee`.
- [ ] `FeatureFormFill` key naming agreed; added to `features.go` (+ `ImplementedFeatures` on ship).
- [ ] Single-KEK / `crypto.Secret` reuse confirmed (no per-app DEK).
- [ ] Extension distribution model decided (Chrome Store vs enterprise pinned) —
      determines the CORS origin lock value in §3.7.
- [ ] Capture-mode origin-validation rules (§6) accepted.

---

## 9. Verified seams (reference)

| Concern | Symbol | Location |
|---|---|---|
| Step-up gate | `stepUp.Fresh(c, tenantID)` | `internal/domain/access/handler.go:234` |
| Step-up middleware | `authn.StepUpMiddleware(StepUpDeps)` | `internal/domain/authn/stepup.go:92` |
| Step-up window default | 1800s | `internal/domain/setting/service.go:360` |
| EE gate | `middleware.RequireFeature(license.Feature)` | `internal/middleware/feature.go:18` |
| Feature keys | `pkg/ee/license/features.go:13-31` | (add `FeatureFormFill`) |
| EE init seam | `RegisterInit(func(*InitContext) error)` | `pkg/ee/registry/seam.go:109/114` |
| EE console seam | `RegisterConsole(func(*gin.RouterGroup))` | `pkg/ee/registry/registry.go:14/19` |
| Actor stamping | `auditctx.With(...)` / `auditctx.From(...)` | `internal/domain/authn/middleware.go:84`, `pkg/auditctx/auditctx.go:50` |
| Event bus | `Bus.Publish(ctx, Event)` | `pkg/event/bus.go:44` |
| Encrypted field | `crypto.Secret` Valuer/Scanner | `pkg/crypto/secret.go:108/125` |
| Master KEK | `crypto.SetSecretMasterKey` | boot: `internal/bootstrap/app.go` |
| Existing vault row | `mxid_app_account.credential crypto.Secret` | `internal/domain/app/model.go:190` |
