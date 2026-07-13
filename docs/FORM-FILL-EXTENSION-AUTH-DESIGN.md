# Form-Fill Browser Extension — Auth & Step-Up-Over-Token

Design/evaluation for how the MV3 extension authenticates to MXID to call the
credential `reveal` endpoint, and how step-up (sudo) works in that model. This is
the crux of B2 (E0.4). Companion to
[FORM-FILL-SSO-DESIGN.md](FORM-FILL-SSO-DESIGN.md) /
[FORM-FILL-SSO-B0-SECURITY-SPEC.md](FORM-FILL-SSO-B0-SECURITY-SPEC.md).

## The hard constraint

`reveal` is gated on a fresh step-up (B0 §3). Step-up freshness is **session-bound**
today:

```
internal/domain/authn/stepup.go:127,176
  sess := <session from gin context>
  return sess != nil && sess.StepUpFresh(time.Now(), window)   // freshness lives ON the session
```

So *how the extension authenticates* decides whether step-up works at all:
- If the extension rides the **portal session cookie**, `StepUpFresh` reads that
  session → works natively.
- If it uses a **Bearer/OIDC token**, there is **no session** → `StepUpFresh`
  fails → step-up must be re-modelled. This is the "step-up-over-token" (suot)
  problem.

MXID's step-up is a self-built session mechanism; it is **not** wired into the
OIDC layer (no `max_age`/`acr`/`auth_time` step-up in `internal/protocol/oidc`).

---

## Option A — reuse the portal session cookie (RECOMMENDED for MVP)

The extension background service worker fetches MXID with `credentials:'include'`;
the portal session cookie rides along.

```
[content script @ wiki.internal] --msg--> [SW @ extension] --fetch(cookie)--> [MXID /formfill/*]
```

- **Step-up: native.** reveal runs under the real portal session. When it returns
  `40133 step_up_required`, the extension opens the portal step-up page in a tab;
  the user does MFA; it stamps *the session*; the extension retries and the same
  session is now fresh. **suot problem does not exist.**
- **What E0 still needs (small):**
  1. CORS on the `/formfill/*` routes: allow origin `chrome-extension://<id>` with
     `Access-Control-Allow-Credentials: true` (lock to the published extension id,
     never `*`).
  2. Portal session cookie `SameSite=None; Secure` so it is sent on the extension's
     cross-site fetch (today it's likely `Lax`).
- **Cost / risk:** `SameSite=None` widens CSRF surface on *all* portal routes (the
  cookie now rides every cross-site request). Mitigations: keep CSRF tokens on
  state-changing portal routes; reveal is origin-locked by CORS so a random site
  cannot read the response; consider a dedicated cookie scoped to `/formfill` if we
  don't want to loosen the main portal cookie.
- **Effort:** ~1–2 days (CORS + cookie flag + verify `StepUpFresh` cross-site).

## Option B — OIDC PKCE token (cleaner isolation, needs suot work)

The extension is an OIDC public client (`chrome.identity.launchWebAuthFlow`,
redirect `https://<ext-id>.chromiumapp.org/`), gets an access token, calls MXID
with `Bearer`.

- **Needs Bearer auth** on the `/formfill/*` routes (today cookie-only) → validate
  the OIDC access token, resolve the user, stamp `auditctx`.
- **Needs a suot solution** (no session → `StepUpFresh` blind):
  - **B-b1: OIDC acr/auth_time.** Extension forces fresh MFA via `prompt=login`
    / `max_age=0` / `acr_values`, gets a token whose `auth_time` is recent and acr
    asserts MFA; reveal checks the token's `auth_time` within the window. Standards-
    clean, BUT MXID does not currently emit/honor these for step-up — it's net-new
    wiring in the OIDC engine. Re-auth opens a web-auth flow every ~30 min.
  - **B-b2: per-user MFA timestamp.** Decouple step-up from the session: record
    "user X passed MFA at T" in Redis keyed by **user id** (not session id). Both
    the cookie path and the token path check that timestamp. Unifies step-up across
    session + token; ~moderate change to `stepup.go` + a Redis key. Recommended if
    we go token.
- **Effort:** ~1.5–2 weeks (Bearer middleware + OIDC client + suot model).

---

## Recommendation

1. **Ship the MVP on Option A** — it makes the extension work end-to-end fastest
   and *eliminates* the suot problem. E0 collapses to CORS + cookie `SameSite=None`
   (the descriptor-sync + reveal + store endpoints already exist).
2. **If/when we want token isolation** (public distribution, no cookie coupling),
   move to Option B with **suot = per-user MFA timestamp (B-b2)** — it's the
   cleanest way to make step-up mechanism-agnostic, and it also lets the *cookie*
   path read the same store, so A and B can coexist during migration.
3. Do **not** invest in OIDC acr/auth_time step-up (B-b1) first — it's the most
   standards-pure but the most net-new wiring and it forces a web-auth round trip
   per window.

## Revised E0 checklist (given Option A for MVP)

- [x] Descriptor-sync endpoint `GET /formfill/apps` (done).
- [x] reveal / store / delete credential endpoints (done, cookie-authed).
- [x] **CORS** — no code needed: the extension origin goes in the existing
      `MXID_SERVER_ALLOWED_ORIGINS` allow-list (comma-separated), e.g.
      `MXID_SERVER_ALLOWED_ORIGINS="https://portal.example.com,chrome-extension://<id>"`.
      `internal/middleware/cors.go` already reflects only allow-listed origins and
      sends `Access-Control-Allow-Credentials: true` + allows `Authorization`.
      (This list also drives CSRF, so the extension's PUT/DELETE pass the Origin check.)
- [x] **Portal cookie `SameSite=None`** — opt-in config `session.cross_site_cookies`
      (env `MXID_SESSION_CROSS_SITE_COOKIES=true`), default **off** (Lax). When on,
      ONLY the portal cookie (`mxid_portal_sid`) flips to `SameSite=None` and is
      forced `Secure`; the console cookie stays Lax. Set + clear paths both honor it
      (`handler.go` setSessionCookieWithRemember / clearSessionCookie).
      **Requires HTTPS** (SameSite=None mandates Secure) — so it cannot be exercised
      on the plain-http dev stack; test on an HTTPS deployment.
- [ ] **Runtime verify** `StepUpChecker.Fresh` resolves the portal session on a
      cross-site extension fetch — the one remaining unknown. Needs HTTPS + a real
      cross-site request; verify when the extension skeleton exists.

**Net:** the backend for Option A is complete and merged behind an opt-in flag.
Enabling the extension in a deployment = set the two env vars above (HTTPS).

Bearer auth, OIDC-client registration, and the suot model are **deferred** — only
needed if we later choose Option B.

## Security invariants (unchanged, both options)

- CORS locked to the exact published extension id, never `*`.
- reveal stays step-up-gated + access-policy-gated + audited; it is the only
  plaintext endpoint. Descriptor sync exposes selectors only, never secrets.
- Capture mode validates recorded selectors resolve within the app's `login_url`
  origin (B0 §6) before saving.
