# Form-Fill — Extension Token Binding (hardening)

Status: **DESIGN**. Closes the residual gap in the Option-A (cookie) auth model:
a malicious browser extension with `host_permissions` for the MXID origin is
**CORS-exempt**, so the cookie-only reveal is readable by *any* such extension
within the step-up window. This binds reveal to a secret only **our** extension
holds. See [FORM-FILL-EXTENSION-AUTH-DESIGN.md](FORM-FILL-EXTENSION-AUTH-DESIGN.md)
and [FORM-FILL-SSO-B0-SECURITY-SPEC.md](FORM-FILL-SSO-B0-SECURITY-SPEC.md).

## The insight

The session cookie is shared across the whole browser origin — every extension
with host permission rides it. What is NOT shared: `chrome.storage.local` is
**isolated per extension** (extension B cannot read extension A's storage), and an
extension's service-worker requests **cannot be intercepted by other extensions**.
So: put a secret in our extension's storage, send it in a header on reveal, and a
different extension — even one with cookie + host permission + a fresh step-up —
cannot produce it.

Reveal then requires **cookie (who) + bound token (which extension) + step-up
(freshness)**. Websites are already blocked by CORS.

## Data model (EE)

```
mxid_formfill_ext_token (NEW)
  id           BIGINT PK
  user_id      BIGINT NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE
  token_hash   VARCHAR(64) NOT NULL      -- sha256(token); plaintext never stored
  device_label VARCHAR(128)              -- "Chrome on WKS-1234" for the user's list
  created_at   TIMESTAMPTZ NOT NULL
  last_used_at TIMESTAMPTZ
  expires_at   TIMESTAMPTZ NOT NULL      -- e.g. 90d; re-pair after
  UNIQUE(token_hash)
  INDEX(user_id)
```

The token itself is a high-entropy random string (`crypto.GenerateClientSecret`-
style), returned to the extension exactly once and stored **only** in
`chrome.storage.local`. The server keeps just the hash.

## Pairing (issuance) — the load-bearing step

Issuance MUST be gated so a rogue extension cannot silently mint its own token
(it has the cookie). Two controls, both applied:

1. **Step-up gated** — `POST /portal/formfill/pair` requires a fresh step-up
   (reuse `StepUpFresh`). A malicious extension cannot produce the user's MFA.
2. **User-visible + explicit** — pairing surfaces in the portal as a new entry in
   **"Connected extensions"** with the device label + time. Best: a short pairing
   *confirmation* the user approves in the portal ("Connect MXID Login? code ABCD")
   so a background rogue pairing can't complete unseen. Minimum: the entry is
   visible and revocable, so a rogue token is spotted + killed.

Flow:
```
extension (first run / on 'needs_pairing') 
   → POST /portal/formfill/pair            (cookie + step-up; body: device_label)
   ← { token }                             (once)
extension stores token in chrome.storage.local
server stores sha256(token) + binding
```

## Reveal (enforced)

```
GET /portal/apps/:id/credential
   headers: Cookie: mxid_portal_sid=…      (identifies the user)
            X-MXID-FormFill-Token: <token> (identifies OUR extension)
```
Server: resolve user from cookie → look up `sha256(token)` for that user →
must exist, not expired → then the existing access-policy + step-up + audit path.
Missing/invalid token → `401 pairing_required` (extension re-pairs). Stamp
`last_used_at`.

A malicious extension has the cookie but not the token → `pairing_required`, and
it cannot pair without passing step-up + showing up in the user's list.

## Management (revocation / visibility)

- `GET /portal/formfill/tokens` → the user's "Connected extensions" (device label,
  last used, created) for a portal settings screen.
- `DELETE /portal/formfill/tokens/:id` → revoke (step-up gated). Admin can revoke
  all for a user (offboarding — tie into the existing offboarding sweep).
- Auto-expire at `expires_at`; extension re-pairs (one more step-up).

## Threat delta

| Attacker | Before (cookie only) | After (token bound) |
|---|---|---|
| Malicious **website** | blocked by CORS | blocked by CORS (unchanged) |
| Malicious **extension**, stale session | blocked by step-up | blocked (no token) |
| Malicious **extension**, fresh step-up window | **CAN read** (residual gap) | **blocked** — has cookie, lacks token; cannot pair without passing step-up *and* appearing in the user's revocable list |

Residual after this: a rogue extension that pairs during a step-up window **and**
the user never notices the extra "Connected extension" entry. Shrunk from "every
reveal" to "one visible, revocable, step-up-gated pairing event". Enterprise
device management (extension allow-listing) removes even that.

## Build estimate

- EE: table + `POST /pair` (step-up) + reveal token check + tokens list/revoke
  routes + offboarding hook — ~3–4 days.
- Extension: pair on first run / on `pairing_required`, store token, send header,
  a "reconnect" affordance in the popup — ~1–2 days.
- Portal FE: "Connected extensions" list + revoke — ~1 day.

## Relation to the OIDC-token path

This is a pragmatic middle ground: keep Option A's cookie for *identity* and add a
bound secret for *this-extension-ness*, gated by step-up at issuance. It gets most
of Option B's isolation without a full OIDC-PKCE + `acr`/`auth_time` rebuild. If a
full token model is later adopted (design §B-b2, per-user MFA timestamp), this
table + pairing folds into it.
