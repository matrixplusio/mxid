package audit

import (
	"encoding/json"
	"sort"

	"github.com/imkerbos/mxid/pkg/event"
)

// detailSchema describes what subset of the event payload should land in
// the audit Detail JSONB column. Two goals:
//
//  1. Stable field set per event_type — the audit UI can render columns
//     deterministically and a SQL JSONB index on common keys (target_id,
//     actor_id, app_id) is meaningful instead of guesswork.
//  2. Outbound filtering — values like `password`, `code`, `secret` that
//     occasionally leak into payloads are stripped before persist.
//
// We allow-list rather than block-list: any field not named here is
// dropped. Unknown event types fall through to a "best effort" set
// covering the common diagnostics keys; this keeps new event_types
// auditable without a migration but loses schema rigor — add an explicit
// schema entry when the event_type stabilizes.
type detailSchema struct {
	allow []string
}

func (d detailSchema) project(in map[string]any) map[string]any {
	out := make(map[string]any, len(d.allow))
	for _, k := range d.allow {
		if v, ok := in[k]; ok && !isSensitiveKey(k) {
			out[k] = v
		}
	}
	return out
}

// sensitiveKeys are dropped even if listed in the allow-list. Mirrors
// the zap redactor's posture: a final defense against a payload that
// accidentally smuggled a secret.
var sensitiveKeys = map[string]struct{}{
	"password":      {},
	"old_password":  {},
	"new_password":  {},
	"password_hash": {},
	"secret":        {},
	"client_secret": {},
	"code":          {}, // OTP / magic-link tokens
	"otp":           {},
	"token":         {},
	"refresh_token": {},
	"access_token":  {},
	"api_key":       {},
	"private_key":   {},
}

func isSensitiveKey(k string) bool {
	_, bad := sensitiveKeys[k]
	return bad
}

// fallbackSchema is the catch-all for unregistered event types. Keeps
// the common diagnostic fields so listings still render.
var fallbackSchema = detailSchema{allow: []string{
	"tenant_id", "user_id", "username", "target_id", "actor_id",
	"app_id", "client_id", "role_id", "group_id", "org_id",
	"resource_id", "resource_type", "session_id",
	"reason", "fields", "from", "to",
	"ip", "user_agent",
}}

var detailSchemas = map[string]detailSchema{
	event.LoginSuccess: {allow: []string{"user_id", "username", "tenant_id", "auth_type", "ip", "user_agent", "session_id"}},
	event.LoginFailed:  {allow: []string{"username", "tenant_id", "reason", "auth_type", "ip", "user_agent"}},
	event.LoginRisk:    {allow: []string{"user_id", "tenant_id", "ip", "user_agent", "reasons"}},
	event.Logout:       {allow: []string{"user_id", "tenant_id", "session_id", "ip", "user_agent"}},

	event.UserCreated:         {allow: []string{"user_id", "tenant_id", "username", "email", "display_name", "actor_id"}},
	event.UserUpdated:         {allow: []string{"user_id", "tenant_id", "actor_id", "fields"}},
	event.UserDeleted:         {allow: []string{"user_id", "tenant_id", "username", "actor_id"}},
	event.UserLocked:          {allow: []string{"user_id", "tenant_id", "actor_id", "reason"}},
	event.UserUnlocked:        {allow: []string{"user_id", "tenant_id", "actor_id"}},
	event.UserPasswordChanged: {allow: []string{"user_id", "tenant_id", "actor_id", "method"}},
	event.UserPIIView:         {allow: []string{"user_id", "target_id", "tenant_id", "fields"}},
	event.UserSuperAdminGrant: {allow: []string{"user_id", "target_id", "tenant_id", "username"}},
	event.UserSuperAdminRevoke: {allow: []string{"user_id", "target_id", "tenant_id", "username"}},
	event.UserOffboarded:       {allow: []string{"user_id", "tenant_id", "username", "actor_id", "sessions_killed"}},

	event.AppCreated:  {allow: []string{"app_id", "tenant_id", "name", "code", "protocol", "actor_id"}},
	event.AppUpdated:  {allow: []string{"app_id", "tenant_id", "fields", "action", "status", "actor_id"}},
	event.AppDeleted:  {allow: []string{"app_id", "tenant_id", "name", "code", "actor_id"}},
	event.AppLaunched: {allow: []string{"app_id", "tenant_id", "user_id", "name", "session_id"}},

	// Security-sensitive app sub-resource changes.
	event.AppAccessGranted:       {allow: []string{"app_id", "tenant_id", "subject_type", "subject_id", "actor_id"}},
	event.AppAccessRevoked:       {allow: []string{"app_id", "tenant_id", "subject_type", "subject_id", "actor_id"}},
	event.AppCertCreated:         {allow: []string{"app_id", "tenant_id", "kid", "actor_id"}},
	event.AppCertDeleted:         {allow: []string{"app_id", "tenant_id", "kid", "cert_id", "actor_id"}},
	event.AppRoleCreated:         {allow: []string{"app_id", "app_group_id", "tenant_id", "role_id", "code", "name", "actor_id"}},
	event.AppRoleUpdated:         {allow: []string{"app_id", "app_group_id", "tenant_id", "role_id", "code", "name", "actor_id"}},
	event.AppRoleDeleted:         {allow: []string{"app_id", "app_group_id", "tenant_id", "role_id", "code", "name", "actor_id"}},
	event.AppRoleBindingCreated:  {allow: []string{"app_id", "app_group_id", "tenant_id", "role_id", "subject_type", "subject_id", "binding_id", "actor_id"}},
	event.AppRoleBindingDeleted:  {allow: []string{"app_id", "app_group_id", "tenant_id", "role_id", "subject_type", "subject_id", "binding_id", "actor_id"}},
	event.AppAccessPolicyCreated: {allow: []string{"app_id", "app_group_id", "tenant_id", "policy_id", "subject_type", "subject_id", "effect", "actor_id"}},
	event.AppAccessPolicyDeleted: {allow: []string{"app_id", "app_group_id", "tenant_id", "policy_id", "subject_type", "subject_id", "effect", "actor_id"}},

	event.OrgCreated:     {allow: []string{"org_id", "tenant_id", "name", "code", "parent_id", "actor_id"}},
	event.OrgUpdated:     {allow: []string{"org_id", "tenant_id", "fields", "actor_id"}},
	event.OrgDeleted:     {allow: []string{"org_id", "tenant_id", "name", "code", "actor_id"}},
	event.OrgMemberMoved: {allow: []string{"user_id", "tenant_id", "from", "to", "actor_id"}},

	event.GroupCreated:       {allow: []string{"group_id", "tenant_id", "name", "code", "actor_id"}},
	event.GroupUpdated:       {allow: []string{"group_id", "tenant_id", "fields", "actor_id"}},
	event.GroupDeleted:       {allow: []string{"group_id", "tenant_id", "name", "actor_id"}},
	event.GroupMemberAdded:   {allow: []string{"group_id", "tenant_id", "user_id"}},
	event.GroupMemberRemoved: {allow: []string{"group_id", "tenant_id", "user_id"}},

	event.TenantCreated: {allow: []string{"id", "tenant_id", "name", "code", "actor_id"}},
	event.TenantUpdated: {allow: []string{"id", "tenant_id", "name", "fields", "actor_id"}},
	event.TenantDeleted: {allow: []string{"id", "tenant_id", "name", "code", "actor_id"}},

	event.IDPCreated: {allow: []string{"id", "tenant_id", "name", "type", "protocol", "actor_id"}},
	event.IDPUpdated: {allow: []string{"id", "tenant_id", "name", "fields", "actor_id"}},
	event.IDPDeleted: {allow: []string{"id", "tenant_id", "name", "type", "actor_id"}},

	event.AppGroupCreated:       {allow: []string{"id", "tenant_id", "name", "code", "actor_id"}},
	event.AppGroupUpdated:       {allow: []string{"id", "tenant_id", "name", "fields", "actor_id"}},
	event.AppGroupDeleted:       {allow: []string{"id", "tenant_id", "name", "actor_id"}},
	event.AppGroupMemberAdded:   {allow: []string{"id", "tenant_id", "app_id"}},
	event.AppGroupMemberRemoved: {allow: []string{"id", "tenant_id", "app_id"}},

	event.SettingsUpdated: {allow: []string{"section", "tenant_id", "fields", "actor_id"}},

	event.ProfileUpdated:  {allow: []string{"user_id", "tenant_id", "fields"}},
	event.APITokenCreated: {allow: []string{"user_id", "tenant_id", "token_id", "name", "scopes"}},
	event.APITokenRevoked: {allow: []string{"user_id", "tenant_id", "token_id"}},

	event.SessionKicked: {allow: []string{"user_id", "session_id", "tenant_id", "actor_id"}},
	event.MFAEnabled:    {allow: []string{"user_id", "tenant_id", "type"}},
	event.MFADisabled:   {allow: []string{"user_id", "tenant_id", "type", "actor_id"}},

	event.OIDCTokenIssued:       {allow: []string{"user_id", "tenant_id", "client_id", "app_id", "scope"}},
	event.OIDCTokenRefreshed:    {allow: []string{"user_id", "tenant_id", "client_id", "app_id"}},
	event.OIDCTokenRevoked:      {allow: []string{"user_id", "tenant_id", "client_id", "app_id"}},
	event.OIDCTokenReuse:        {allow: []string{"user_id", "tenant_id", "client_id", "app_id"}},
	event.OIDCConsentGranted:    {allow: []string{"user_id", "tenant_id", "client_id", "app_id", "scope"}},
	event.OIDCConsentRevoked:    {allow: []string{"user_id", "tenant_id", "client_id", "app_id", "actor_id"}},
	event.OIDCBackchannelLogout: {allow: []string{"user_id", "tenant_id", "client_id", "app_id", "session_id"}},
}

// projectDetail picks the schema-allowed subset of payload for the given
// event_type, drops any sensitive keys, and returns the JSON-encoded
// bytes. Returns "{}" on encode failure so the column stays valid.
func projectDetail(eventType string, payload map[string]any) json.RawMessage {
	schema, ok := detailSchemas[eventType]
	if !ok {
		schema = fallbackSchema
	}
	picked := schema.project(payload)
	data, err := json.Marshal(picked)
	if err != nil {
		return json.RawMessage("{}")
	}
	return data
}

// RegisteredEventTypes returns the sorted list of event_types this
// package knows a schema for. Useful for the console UI to render a
// filter dropdown without inventing the list there.
func RegisteredEventTypes() []string {
	out := make([]string, 0, len(detailSchemas))
	for k := range detailSchemas {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
