# Editions — Community (CE) vs Enterprise (EE)

MXID ships as an open-core product. **Community Edition (CE)** is the default and
fully usable on its own. **Enterprise Edition (EE)** unlocks additional features
with a signed license.

## Feature matrix

| Capability | CE | EE |
|------------|:--:|:--:|
| Password login, sessions, TOTP MFA | ✅ | ✅ |
| OIDC / SAML / CAS / JWT protocols | ✅ | ✅ |
| Users / orgs / groups, RBAC | ✅ | ✅ |
| SMTP email, basic audit | ✅ | ✅ |
| **Single-tenant** (one identity domain per deployment) | ✅ | ✅ |
| **External IdP login** (social / enterprise SSO) | ❌ | ✅ |
| **Branding / white-label** (logo, colors, login page) | ❌ | ✅ |
| Conditional access, WebAuthn/passkeys, SCIM, SMS, advanced step-up | ❌ | ✅ |
| **Form-fill SSO (SWA)** — browser-extension auto-login for password-only web apps | ❌ | ✅ |

Feature keys (in the license payload): `external_idp`, `branding`,
`conditional_access`, `webauthn`, `scim`, `advanced_stepup`, `sms`, `form_fill`.

### CE capabilities

- **App template marketplace** (CE): create apps from built-in onboarding
  presets (Feishu, DingTalk, WeCom, GitLab, Grafana, Jenkins, Jira,
  Confluence, JumpServer). Templates are declarative and contain no secrets;
  template-created apps run the same validation as hand-filled ones.

## How editions are built (architecture)

Three repositories, single source of truth, no fork:

```
github.com/imkerbos/mxid            public   CE product + app.Run() + pkg/ee/{license,registry}
github.com/imkerbos/mxid-ee         private  EE features; wraps app.Run(), garble-obfuscated
github.com/imkerbos/license-authority  private  per-product Ed25519 signing keys + issuance
```

Two layers of EE gating:

1. **Runtime-gated** (`branding`, `conditional_access`): the code
   lives in the CE binary — these features rely on foundational schema that CE
   already contains (and grandfathers on expiry). `middleware.RequireFeature` /
   `license.Current().Has()` returns 403 / locks the UI unless the license grants
   the feature. Expiry reverts to CE limits; existing data is grandfathered (see
   §Expiry below).
2. **Code-separated** (`external_idp`, `webauthn`, `scim`, `advanced_stepup`,
   `sms`, `form_fill`, and other high-value features): the implementation lives ONLY in the
   private `mxid-ee` repo. EE feature packages register into `pkg/ee/registry`
   from their `init()`; the CE binary imports none, so the code is *physically
   absent* from it — there is nothing to patch out. Verified: the CE binary
   contains zero EE symbols. The EE binary is built with `garble` (symbol +
   control-flow obfuscation) as a further anti-tamper measure.

The license signature is the hard control: it is verified against an embedded
Ed25519 **public** key, so an operator cannot forge or edit a license. The
private signing key lives only in `license-authority`.

## Running CE

CE images are public on GHCR:

```
ghcr.io/imkerbos/mxid       # backend
ghcr.io/imkerbos/mxid-web   # nginx + SPAs (shared by both editions)
```

`.env` (see [DEPLOYMENT.md](DEPLOYMENT.md)) with `MXID_TAG` set, then
`docker compose up -d`. No license in the DB → CE.

## Running EE

The EE backend is a separate, **private** image (`ghcr.io/imkerbos/mxid-ee`,
garble-obfuscated). The web image is shared with CE. Select it via the EE
compose overlay in `.env`:

```ini
# external DB:
COMPOSE_FILE=deploy/compose/docker-compose.yml:deploy/compose/docker-compose.ee.yml
# self-contained (containerized Postgres + Redis):
# COMPOSE_FILE=deploy/compose/docker-compose.yml:deploy/compose/docker-compose.standalone.yml:deploy/compose/docker-compose.ee.yml

MXID_TAG=v0.0.2
```

```bash
docker login ghcr.io            # EE image is private — needs a read:packages token
docker compose pull
docker compose up -d
```

Then activate the license in the console (see below). The EE *image* and the
*license* are independent: the image provides the code-separated features; the
license unlocks them at runtime.

> **CE image + EE license** unlocks the *runtime-gated* features
> (`branding` / `conditional_access`), but NOT the
> code-separated ones (`external_idp`, `webauthn`, `scim`, …) — those code paths
> do not exist in the CE binary at all; accessing them returns 404.
> EE customers run `mxid-ee`.

> **Switching CE → EE** means pulling the `mxid-ee` image. The license is stored
> in the database and survives the image swap untouched — no re-activation needed.

## Activation

A license is an Ed25519-signed token issued by `license-authority`:

```bash
# in the license-authority repo
go run ./cmd/sign -product mxid \
  -customer "Acme Corp" -features all -exp 2027-01-01 -max-users 500
```

Activate in the **console** — Settings → License: paste the token and save. It's
verified, stored in the database, and the edition flips immediately (hot-reload,
no restart). Being DB-persisted, it survives image swaps and restarts — pull a
new image, it reads the same license. There is no env/file activation.

The console License page shows the resolved edition, customer, expiry, and
unlocked features. Only the token is editable; everything else is derived from
the verified signature.

`GET /api/v1/system/info` exposes `edition` + `features`. The `features` list
reflects only what the running binary actually contains: code-separated features
(`external_idp`, `webauthn`, `scim`, …) appear only when the **EE binary** is
running, because their registration happens in `pkg/ee/registry` at `init()` time
— if the code is absent, the feature is never registered and never listed.
Activating an EE license on the CE image does *not* cause `external_idp` to
appear in `/system/info`; it will still 404.

The frontend gates EE UI on these fields (e.g. the branding page is locked with
an upsell banner in CE).

### Install binding (anti-reuse)

A license is **portable by default** — it runs on any installation. To stop one
token being reused across many deployments, issue an **install-bound** license:

- Each install has a fingerprint = `HMAC(macKey, install_uuid | postgres
  system_identifier)` — bound to the DB cluster, derived offline. It's shown on
  the console License page (Settings → License).
- The operator gives that fingerprint to the vendor, who signs a bound token:
  `cmd/sign -install <fingerprint>`.
- A bound token only verifies on its installation; on any other it fails with
  state `mismatch` and the instance runs as CE. Copying the token + a DB dump to
  a different cluster changes `system_identifier`, so the fingerprint no longer
  matches.

## Limits & enforcement

| Resource | CE | EE |
|----------|----|----|
| Users | **100** (`CEMaxUsers`) | unlimited (or the license's `max_users`) |
| Apps / orgs / groups / roles / API tokens | unlimited | unlimited |
| Audit retention | unlimited (default 365d, console-configurable) | unlimited |
| External IdP · branding · conditional access · WebAuthn · SCIM · SMS · advanced step-up | ❌ | ✅ |

| Control | Source | Enforced |
|---------|--------|----------|
| Feature set | signed `features[]` | route gates + UI + (code-separated) absence from the CE binary |
| Expiry | signed `exp` | expired → reverts to CE limits (see below) |
| Product binding | signed `product` | a license for another product is rejected |
| User cap | edition (`license.Current()`) | create blocked at the cap; existing rows grandfathered |

### Expiry — graceful downgrade, data grandfathered

An expired license does **not** delete anything or break logins. The instance
reverts to **CE limits**, and existing data over those limits is grandfathered:

- Logins / SSO / token issuance keep working — unaffected.
- User count ≤ 100 → you can still create up to 100. Count already > 100 (grown
  under EE) → all existing users keep working, but **no new users** until renewal.
- External IdPs configured under EE keep functioning; you can't create new ones.
  Applied branding stays; you can't edit it.

Renew by pasting a fresh token in the console — the cap/features lift instantly.
Offline by design: no online revocation; bound risk with `-exp` + renewal.

## Issuing licenses (vendor)

See the `license-authority` repo: `cmd/keygen` (one key pair per product, public
half embedded in the product), `cmd/sign` (issue a token), `products/<id>.yaml`
(feature catalog), `customers/` (issuance records). Private keys never leave the
authority repo / secrets manager.

## License

Community Edition is AGPL-3.0 ([LICENSE](../LICENSE)). The Enterprise Edition
(`mxid-ee` + EE-gated features) is governed by a commercial license
([LICENSE.EE](../LICENSE.EE)). Copyright © 2026 MatrixPlus.
