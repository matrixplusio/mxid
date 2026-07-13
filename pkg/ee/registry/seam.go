package registry

import (
	"context"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/session"
)

// This file is the dependency-injection seam used by heavier EE features (e.g.
// external IdP) that need more than a console route group: they require the
// bootstrap App (DB/Redis/router/groups), plus a handful of CE-domain hooks the
// EE module cannot construct itself (account linking lives in the CE user
// domain; tenant-code resolution and console authorization live in CE too).
//
// An EE feature registers an Initializer from its init(); app/run.go calls
// RunInit once at startup with a populated InitContext. CE imports no EE feature
// package, so no Initializer is registered and RunInit is a no-op.

// ResolverInput is the neutral account-linking contract between an external IdP
// callback (EE) and the CE user domain. It mirrors user.ExternalLoginInput but
// lives here so neither side imports the other: CE's adapter and the EE handler
// both reference this type. Carries every field needed to link an existing user
// or auto-provision a new one.
type ResolverInput struct {
	TenantID     int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	Username     string
	DisplayName  string
	Email        string
	Phone        string
	Avatar       string
	Raw          map[string]any
	AutoCreate   bool
	DefaultOrgID *int64
}

// ExternalLoginFunc resolves an external identity to a local user, returning the
// user id and username. Implemented by the CE user domain.
type ExternalLoginFunc func(ctx context.Context, in *ResolverInput) (userID int64, username string, err error)

// TenantByCodeFunc maps a tenant code to its id (0 when unknown). Implemented by
// the CE tenant domain.
type TenantByCodeFunc func(ctx context.Context, code string) int64

// UpdateLastLoginFunc stamps last_login_at / last_login_ip after a successful
// login. The CE password engine does this in completeLogin; external-IdP logins
// run outside that engine (and the CE resolver seam has no client IP), so the EE
// handler must call this after minting the session or the user's "last login"
// never reflects a federated sign-in. Implemented by the CE user domain.
type UpdateLastLoginFunc func(ctx context.Context, userID int64, ip string) error

// ConsoleGateFunc authorizes an external identity for console login: it must
// reject break-glass built-in accounts and users without any console
// permission. Implemented in CE (authz + user repo).
type ConsoleGateFunc func(ctx context.Context, tenantID, userID int64) error

// ExternalURLsFunc returns the externally-reachable issuer (the OAuth callback
// target), portal, and console URLs for a tenant — read at REQUEST time from the
// CE settings store so external-IdP callbacks use the admin-configured URLs
// rather than a boot-time env default. Any empty return value means "fall back
// to the boot-time env value". Implemented in CE over settings.ExternalURLs (it
// injects the tenant scope itself, since external-IdP start runs pre-login
// without one). Unifies external URL config across CE protocols and EE IdP.
type ExternalURLsFunc func(ctx context.Context, tenantID int64) (issuer, portal, console string)

// OutboxHandler processes a durable outbox message. payload is the raw JSON the
// producer enqueued. Returning an error reschedules the message with backoff
// (dead-lettered after max attempts); nil marks it delivered. Must be
// idempotent — at-least-once delivery means a message can be retried after a
// crash mid-processing. Neutral ([]byte) so the EE module needs no CE internal
// type.
type OutboxHandler func(ctx context.Context, payload []byte) error

// OutboxRegisterFunc binds an EE handler to an outbox message kind. Implemented
// in CE over the outbox worker. The CE binary registers no EE handler and never
// enqueues an EE-only kind, so the kind simply has no consumer there.
type OutboxRegisterFunc func(kind string, h OutboxHandler)

// ProvisioningConfigFunc returns an app's live, decrypted outbound-provisioning
// config. enabled=false means no downstream deprovision should run. Implemented
// in CE over the provisioning domain so the EE SCIM connector never touches the
// config table or the master key.
type ProvisioningConfigFunc func(ctx context.Context, appID int64) (enabled bool, connector, baseURL, token string, err error)

// InitContext carries everything an EE feature needs from CE at startup. App
// exposes DB/Redis/router/route-groups/config; the func hooks bridge to CE
// domains the EE module must not import.
type InitContext struct {
	App          *bootstrap.App
	SessionMgr   *session.Manager
	ExternalLogin ExternalLoginFunc
	TenantByCode TenantByCodeFunc
	ConsoleGate  ConsoleGateFunc
	ExternalURLs ExternalURLsFunc
	// UpdateLastLogin stamps last-login after a federated sign-in (external IdP
	// runs outside the CE password engine that normally owns the stamp).
	UpdateLastLogin UpdateLastLoginFunc
	// OutboxRegister binds an EE outbox handler (e.g. SCIM deprovision delivery).
	OutboxRegister OutboxRegisterFunc
	// ProvisioningConfig reads an app's outbound-provisioning credentials at
	// delivery time (the EE SCIM connector uses it).
	ProvisioningConfig ProvisioningConfigFunc
}

// Initializer wires one EE feature. Returning an error aborts startup.
type Initializer func(*InitContext) error

var initializers []Initializer

// RegisterInit adds an EE feature initializer. Called from an EE package init().
func RegisterInit(i Initializer) {
	if i != nil {
		initializers = append(initializers, i)
	}
}

// RunInit invokes every registered EE initializer with the given context. No EE
// module imported (CE) → no initializers → no-op.
func RunInit(ic *InitContext) error {
	for _, i := range initializers {
		if err := i(ic); err != nil {
			return err
		}
	}
	return nil
}
