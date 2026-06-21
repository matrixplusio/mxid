# App Template Marketplace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let admins create an application from a pre-filled template (Feishu, Jira, JumpServer, …) instead of hand-filling every protocol field.

**Architecture:** Built-in templates are JSON files embedded into the CE binary via `go:embed`, parsed and validated once at startup. Two read-only console endpoints expose the catalog. The console create-app flow gains a template-picker step that pre-fills the existing create form and submits through the **unchanged** `POST /apps` path — so every template-created app runs the same validation as a hand-filled one.

**Tech Stack:** Go 1.25.11 (Gin + `embed`), React 19 + TypeScript + Tailwind v4, pnpm workspaces, `@mxid/shared` UI/API primitives.

## Global Constraints

- Go toolchain pinned at **1.25.11**.
- Templates are **CE** (not license-gated). No `RequireFeature`.
- Templates carry **NO secrets** — declarative protocol defaults + placeholders only. Loader rejects secret-like default keys.
- Reuse the existing `POST /api/v1/console/apps` create + validation path. Do **not** add a template-specific create endpoint.
- Console write/read routes gated with `authz.Require(...)`. Template reads use `app.read`.
- Backend tests: stdlib `testing` (no testify), `t.Fatalf` style, `package app`.
- **No frontend test runner exists** — frontend tasks are verified with `pnpm -C apps/console exec tsc --noEmit` plus a manual check. Do not invent a test runner.
- Every frontend write keeps existing `toast.success` / `toast.error` feedback. UI primitives from `@mxid/shared` / `../../components/ui`.
- i18n strings added to **both** `en-US.ts` and `zh-CN.ts`.
- Commit messages: Conventional Commits, English, **no AI attribution**, no `Co-Authored-By`.
- Do not auto-commit beyond the per-task commits defined here.

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/domain/app/template.go` (create) | `Template` / `TemplateField` types, `go:embed` loader, `GetTemplate`, `Templates`, validation |
| `internal/domain/app/templates/*.json` (create) | One JSON per built-in template (data) |
| `internal/domain/app/template_test.go` (create) | Loader + data validation tests |
| `internal/domain/app/handler.go` (modify) | Mount `/app-templates` routes + `ListTemplates`/`GetTemplate` handlers |
| `internal/domain/app/template_response.go` (create) | List-item DTO + mapping (detail returns the `Template` as-is) |
| `internal/domain/app/template_response_test.go` (create) | DTO mapping test |
| `web/packages/shared/src/types/index.ts` (modify) | `AppTemplate`, `AppTemplateField`, `AppTemplateListItem` types |
| `web/packages/shared/src/api/app.ts` (modify) | `appApi.listTemplates` / `appApi.getTemplate` |
| `web/apps/console/src/pages/apps/index.tsx` (modify) | Template-picker step + prefill + dynamic fields in the create flow |
| `web/packages/shared/src/i18n/locales/en-US.ts` + `zh-CN.ts` (modify) | Picker UI strings |
| `docs/EDITIONS.md` (modify) | Note: template marketplace is CE |

---

### Task 1: Template type + embed loader

**Files:**
- Create: `internal/domain/app/template.go`
- Create: `internal/domain/app/templates/feishu.json`
- Test: `internal/domain/app/template_test.go`

**Interfaces:**
- Produces:
  - `type TemplateField struct { Key, Label, Type, Placeholder, Target string; Required bool }`
  - `type Template struct { Key, Name, Icon, Category, Protocol, ClientType, SubjectStrategy, Description, DocMD string; Defaults map[string]any; Fields []TemplateField }`
  - `func Templates() []Template` — all built-ins, sorted by `Category` then `Name`
  - `func GetTemplate(key string) (Template, error)` — `ErrTemplateNotFound` on miss
  - `var ErrTemplateNotFound = errors.New("template not found")`

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/app/template_test.go
package app

import (
	"errors"
	"testing"
)

func TestTemplatesLoad(t *testing.T) {
	ts := Templates()
	if len(ts) == 0 {
		t.Fatalf("expected built-in templates, got 0")
	}
	var found bool
	for _, tpl := range ts {
		if tpl.Key == "feishu" {
			found = true
			if tpl.Protocol != ProtocolOIDC {
				t.Fatalf("feishu protocol = %q, want oidc", tpl.Protocol)
			}
		}
	}
	if !found {
		t.Fatalf("feishu template not loaded")
	}
}

func TestGetTemplate(t *testing.T) {
	if _, err := GetTemplate("feishu"); err != nil {
		t.Fatalf("GetTemplate(feishu): %v", err)
	}
	if _, err := GetTemplate("does-not-exist"); !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("GetTemplate(miss) err = %v, want ErrTemplateNotFound", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/app/ -run 'TestTemplatesLoad|TestGetTemplate' -v`
Expected: FAIL — `undefined: Templates` / `undefined: GetTemplate`.

- [ ] **Step 3: Write the loader**

```go
// internal/domain/app/template.go
package app

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

//go:embed templates/*.json
var templateFS embed.FS

// ErrTemplateNotFound is returned by GetTemplate for an unknown key.
var ErrTemplateNotFound = errors.New("template not found")

// TemplateField is a single differential input the create wizard asks for
// after a template is chosen (the rest is pre-filled from Defaults).
type TemplateField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Type        string `json:"type"` // "text" | "textarea"
	Placeholder string `json:"placeholder,omitempty"`
	Required    bool   `json:"required,omitempty"`
	// Target tells the wizard where the value goes:
	//   "redirect_uris"           -> top-level redirect URIs (newline/comma split)
	//   "home_url"                -> top-level home URL
	//   "protocol_config.<name>"  -> a key inside protocol_config
	Target string `json:"target"`
}

// Template is a declarative app-onboarding preset. It NEVER contains secrets.
type Template struct {
	Key             string          `json:"key"`
	Name            string          `json:"name"`
	Icon            string          `json:"icon,omitempty"`
	Category        string          `json:"category"`
	Protocol        string          `json:"protocol"`
	ClientType      string          `json:"client_type"`
	SubjectStrategy string          `json:"subject_strategy,omitempty"`
	Description     string          `json:"description,omitempty"`
	DocMD           string          `json:"doc_md,omitempty"`
	Defaults        map[string]any  `json:"defaults,omitempty"` // merged into protocol_config
	Fields          []TemplateField `json:"fields,omitempty"`
}

var (
	loadOnce  sync.Once
	loaded    []Template
	loadedIdx map[string]Template
	loadErr   error
)

// secretLikeKeys are rejected in Defaults — templates must stay declarative.
var secretLikeKeys = map[string]bool{
	"client_secret": true,
	"secret":        true,
	"password":      true,
}

func validProtocol(p string) bool {
	return p == ProtocolOIDC || p == ProtocolSAML || p == ProtocolCAS
}

func loadTemplates() {
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		loadErr = fmt.Errorf("read templates dir: %w", err)
		return
	}
	idx := make(map[string]Template, len(entries))
	out := make([]Template, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := templateFS.ReadFile("templates/" + e.Name())
		if err != nil {
			loadErr = fmt.Errorf("read %s: %w", e.Name(), err)
			return
		}
		var tpl Template
		if err := json.Unmarshal(b, &tpl); err != nil {
			loadErr = fmt.Errorf("parse %s: %w", e.Name(), err)
			return
		}
		if tpl.Key == "" || tpl.Name == "" {
			loadErr = fmt.Errorf("%s: key and name are required", e.Name())
			return
		}
		if !validProtocol(tpl.Protocol) {
			loadErr = fmt.Errorf("%s: invalid protocol %q", e.Name(), tpl.Protocol)
			return
		}
		for k := range tpl.Defaults {
			if secretLikeKeys[k] {
				loadErr = fmt.Errorf("%s: defaults must not contain secret key %q", e.Name(), k)
				return
			}
		}
		if _, dup := idx[tpl.Key]; dup {
			loadErr = fmt.Errorf("duplicate template key %q", tpl.Key)
			return
		}
		idx[tpl.Key] = tpl
		out = append(out, tpl)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	loaded, loadedIdx = out, idx
}

func ensureLoaded() {
	loadOnce.Do(loadTemplates)
}

// Templates returns all built-in templates, sorted by category then name.
// Panics if any embedded template is malformed (fail-fast at boot).
func Templates() []Template {
	ensureLoaded()
	if loadErr != nil {
		panic(loadErr)
	}
	return loaded
}

// GetTemplate returns one template by key, or ErrTemplateNotFound.
func GetTemplate(key string) (Template, error) {
	ensureLoaded()
	if loadErr != nil {
		return Template{}, loadErr
	}
	tpl, ok := loadedIdx[key]
	if !ok {
		return Template{}, ErrTemplateNotFound
	}
	return tpl, nil
}
```

```json
// internal/domain/app/templates/feishu.json
{
  "key": "feishu",
  "name": "飞书 Feishu",
  "category": "collaboration",
  "protocol": "oidc",
  "client_type": "web_app",
  "description": "飞书企业应用,通过 OIDC 接入 MXID 单点登录。",
  "doc_md": "1. 飞书开放平台创建企业自建应用。\n2. 安全设置 → 重定向 URL 填下方回调地址。\n3. 把 MXID 的 Client ID / Secret 配回飞书。",
  "defaults": {
    "scopes": ["openid", "profile", "email"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_post",
    "pkce_required": true
  },
  "fields": [
    { "key": "redirect_uris", "label": "回调地址 (Redirect URIs)", "type": "textarea", "placeholder": "https://open.feishu.cn/...", "required": true, "target": "redirect_uris" }
  ]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/app/ -run 'TestTemplatesLoad|TestGetTemplate' -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/domain/app/template.go internal/domain/app/templates/feishu.json internal/domain/app/template_test.go
git commit -m "feat(app): add embedded app-template loader"
```

---

### Task 2: Built-in template catalog (9 templates)

**Files:**
- Create: `internal/domain/app/templates/{dingtalk,wecom,gitlab,grafana,jenkins,jira,confluence,jumpserver}.json`
- Test: `internal/domain/app/template_test.go` (append)

**Interfaces:**
- Consumes: `Template`, `Templates()` from Task 1.
- Produces: a catalog of ≥9 templates spanning oidc/saml/cas.

- [ ] **Step 1: Write the failing test (append)**

```go
// append to internal/domain/app/template_test.go
func TestCatalogCoverage(t *testing.T) {
	ts := Templates()
	if len(ts) < 9 {
		t.Fatalf("catalog has %d templates, want >= 9", len(ts))
	}
	want := map[string]bool{
		"feishu": false, "dingtalk": false, "wecom": false, "gitlab": false,
		"grafana": false, "jenkins": false, "jira": false, "confluence": false,
		"jumpserver": false,
	}
	protos := map[string]bool{}
	for _, tpl := range ts {
		if _, ok := want[tpl.Key]; ok {
			want[tpl.Key] = true
		}
		protos[tpl.Protocol] = true
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("template %q missing from catalog", k)
		}
	}
	for _, p := range []string{ProtocolOIDC, ProtocolSAML, ProtocolCAS} {
		if !protos[p] {
			t.Fatalf("catalog has no %s template", p)
		}
	}
}

func TestJumpServerIsCAS(t *testing.T) {
	tpl, err := GetTemplate("jumpserver")
	if err != nil {
		t.Fatalf("jumpserver: %v", err)
	}
	if tpl.Protocol != ProtocolCAS {
		t.Fatalf("jumpserver protocol = %q, want cas (community edition only ships CAS)", tpl.Protocol)
	}
	if tpl.SubjectStrategy != "username" {
		t.Fatalf("jumpserver subject_strategy = %q, want username (avoid numeric principal)", tpl.SubjectStrategy)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/app/ -run 'TestCatalogCoverage|TestJumpServerIsCAS' -v`
Expected: FAIL — templates missing.

- [ ] **Step 3: Create the 8 JSON files**

```json
// dingtalk.json
{ "key": "dingtalk", "name": "钉钉 DingTalk", "category": "collaboration", "protocol": "oidc", "client_type": "web_app",
  "description": "钉钉企业应用,OIDC 接入。",
  "doc_md": "1. 钉钉开发者后台创建应用。\n2. 配置回调域名为下方回调地址。",
  "defaults": { "scopes": ["openid","profile","email"], "grant_types": ["authorization_code"], "response_types": ["code"], "token_endpoint_auth_method": "client_secret_post", "pkce_required": true },
  "fields": [ { "key": "redirect_uris", "label": "回调地址", "type": "textarea", "required": true, "target": "redirect_uris" } ] }
```

```json
// wecom.json
{ "key": "wecom", "name": "企业微信 WeCom", "category": "collaboration", "protocol": "oidc", "client_type": "web_app",
  "description": "企业微信自建应用,OIDC 接入。",
  "doc_md": "1. 企业微信管理后台创建自建应用。\n2. 配置可信域名与回调地址。",
  "defaults": { "scopes": ["openid","profile","email"], "grant_types": ["authorization_code"], "response_types": ["code"], "token_endpoint_auth_method": "client_secret_post", "pkce_required": true },
  "fields": [ { "key": "redirect_uris", "label": "回调地址", "type": "textarea", "required": true, "target": "redirect_uris" } ] }
```

```json
// gitlab.json
{ "key": "gitlab", "name": "GitLab", "category": "devtools", "protocol": "oidc", "client_type": "web_app",
  "description": "GitLab 通过 OpenID Connect (OmniAuth) 接入。社区版 SAML 受限,默认走 OIDC。",
  "doc_md": "1. GitLab 服务端 omniauth 配置 openid_connect provider。\n2. discovery 指向 MXID 的 /.well-known/openid-configuration。\n3. redirect_uri = https://<gitlab>/users/auth/openid_connect/callback",
  "defaults": { "scopes": ["openid","profile","email"], "grant_types": ["authorization_code"], "response_types": ["code"], "token_endpoint_auth_method": "client_secret_post", "pkce_required": true },
  "fields": [ { "key": "redirect_uris", "label": "Redirect URI", "type": "textarea", "placeholder": "https://gitlab.example.com/users/auth/openid_connect/callback", "required": true, "target": "redirect_uris" } ] }
```

```json
// grafana.json
{ "key": "grafana", "name": "Grafana", "category": "devtools", "protocol": "oidc", "client_type": "web_app",
  "description": "Grafana generic OAuth/OIDC 接入。",
  "doc_md": "1. grafana.ini [auth.generic_oauth] 配置。\n2. auth/token/api_url 指向 MXID OIDC 端点。\n3. redirect_uri = https://<grafana>/login/generic_oauth",
  "defaults": { "scopes": ["openid","profile","email"], "grant_types": ["authorization_code"], "response_types": ["code"], "token_endpoint_auth_method": "client_secret_post", "pkce_required": true },
  "fields": [ { "key": "redirect_uris", "label": "Redirect URI", "type": "textarea", "placeholder": "https://grafana.example.com/login/generic_oauth", "required": true, "target": "redirect_uris" } ] }
```

```json
// jenkins.json
{ "key": "jenkins", "name": "Jenkins", "category": "devtools", "protocol": "oidc", "client_type": "web_app",
  "description": "Jenkins 通过 OIDC 插件接入。",
  "doc_md": "1. 安装 Jenkins oic-auth 插件。\n2. 配置 well-known endpoint 与 client 凭证。\n3. redirect_uri = https://<jenkins>/securityRealm/finishLogin",
  "defaults": { "scopes": ["openid","profile","email"], "grant_types": ["authorization_code"], "response_types": ["code"], "token_endpoint_auth_method": "client_secret_post", "pkce_required": true },
  "fields": [ { "key": "redirect_uris", "label": "Redirect URI", "type": "textarea", "placeholder": "https://jenkins.example.com/securityRealm/finishLogin", "required": true, "target": "redirect_uris" } ] }
```

```json
// jira.json
{ "key": "jira", "name": "Jira (Data Center)", "category": "atlassian", "protocol": "saml", "client_type": "web_app",
  "description": "Atlassian Jira Data Center,通过 SAML 2.0 接入。",
  "doc_md": "1. Jira 管理 → SAML SSO 配置。\n2. 导入 MXID 的 SAML metadata。\n3. 填写下方 SP Entity ID 与 ACS URL。",
  "defaults": { "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "sign_assertions": true, "sign_response": false },
  "fields": [
    { "key": "sp_entity_id", "label": "SP Entity ID", "type": "text", "placeholder": "https://jira.example.com", "required": true, "target": "protocol_config.sp_entity_id" },
    { "key": "acs_url", "label": "ACS URL", "type": "text", "placeholder": "https://jira.example.com/plugins/servlet/samlconsumer", "required": true, "target": "protocol_config.acs_url" }
  ] }
```

```json
// confluence.json
{ "key": "confluence", "name": "Confluence (Data Center)", "category": "atlassian", "protocol": "saml", "client_type": "web_app",
  "description": "Atlassian Confluence Data Center,通过 SAML 2.0 接入。",
  "doc_md": "1. Confluence 管理 → SAML SSO 配置。\n2. 导入 MXID 的 SAML metadata。\n3. 填写下方 SP Entity ID 与 ACS URL。",
  "defaults": { "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "sign_assertions": true, "sign_response": false },
  "fields": [
    { "key": "sp_entity_id", "label": "SP Entity ID", "type": "text", "placeholder": "https://confluence.example.com", "required": true, "target": "protocol_config.sp_entity_id" },
    { "key": "acs_url", "label": "ACS URL", "type": "text", "placeholder": "https://confluence.example.com/plugins/servlet/samlconsumer", "required": true, "target": "protocol_config.acs_url" }
  ] }
```

```json
// jumpserver.json
{ "key": "jumpserver", "name": "JumpServer", "category": "devtools", "protocol": "cas", "client_type": "web_app", "subject_strategy": "username",
  "description": "JumpServer 社区版仅支持 CAS。subject_strategy 固定 username,避免 cas:user 变成数字 ID。",
  "doc_md": "1. JumpServer 系统设置 → 认证 → CAS。\n2. Server URL 指向 MXID 的 /cas/<app_code>。\n3. 在 Service URL 白名单填 JumpServer 回调地址。",
  "defaults": { "ticket_ttl": 30 },
  "fields": [
    { "key": "service_urls", "label": "Service URL 白名单 (逗号分隔)", "type": "textarea", "placeholder": "https://jumpserver.example.com/core/auth/cas/callback/", "required": true, "target": "protocol_config.service_urls" }
  ] }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/app/ -run 'TestCatalogCoverage|TestJumpServerIsCAS' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/domain/app/templates/ internal/domain/app/template_test.go
git commit -m "feat(app): add built-in template catalog (feishu/jira/jumpserver/…)"
```

---

### Task 3: Console template endpoints

**Files:**
- Create: `internal/domain/app/template_response.go`
- Test: `internal/domain/app/template_response_test.go`
- Modify: `internal/domain/app/handler.go` (route block + two handlers)

**Interfaces:**
- Consumes: `Templates()`, `GetTemplate(key)`, `ErrTemplateNotFound` (Task 1); `response.OK` / `response.NotFound` from `pkg/response`.
- Produces:
  - `type TemplateListItem struct { Key, Name, Icon, Category, Protocol, Description string }`
  - `func ToTemplateListItems(ts []Template) []TemplateListItem`
  - Routes: `GET /api/v1/console/app-templates`, `GET /api/v1/console/app-templates/:key` (both `authz.Require("app.read", nil)`)

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/app/template_response_test.go
package app

import "testing"

func TestToTemplateListItems(t *testing.T) {
	in := []Template{{
		Key: "feishu", Name: "飞书", Icon: "x", Category: "collaboration",
		Protocol: "oidc", Description: "desc",
		DocMD: "SHOULD NOT LEAK", // detail-only field must be absent from list items
	}}
	out := ToTemplateListItems(in)
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	if out[0].Key != "feishu" || out[0].Protocol != "oidc" || out[0].Category != "collaboration" {
		t.Fatalf("unexpected item: %+v", out[0])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/app/ -run TestToTemplateListItems -v`
Expected: FAIL — `undefined: ToTemplateListItems`.

- [ ] **Step 3: Write the DTO mapper**

```go
// internal/domain/app/template_response.go
package app

// TemplateListItem is the lightweight catalog entry (no doc_md / defaults / fields).
type TemplateListItem struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Icon        string `json:"icon,omitempty"`
	Category    string `json:"category"`
	Protocol    string `json:"protocol"`
	Description string `json:"description,omitempty"`
}

// ToTemplateListItems projects full templates down to catalog entries.
func ToTemplateListItems(ts []Template) []TemplateListItem {
	out := make([]TemplateListItem, len(ts))
	for i, tpl := range ts {
		out[i] = TemplateListItem{
			Key:         tpl.Key,
			Name:        tpl.Name,
			Icon:        tpl.Icon,
			Category:    tpl.Category,
			Protocol:    tpl.Protocol,
			Description: tpl.Description,
		}
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/app/ -run TestToTemplateListItems -v`
Expected: PASS.

- [ ] **Step 5: Add the handlers and routes**

In `internal/domain/app/handler.go`, inside `RegisterRoutes`, add a new group **after** the `apps` group block:

```go
	templates := rg.Group("/app-templates")
	{
		templates.GET("", authz.Require("app.read", nil), h.ListTemplates)
		templates.GET("/:key", authz.Require("app.read", nil), h.GetTemplate)
	}
```

Add the handler methods (anywhere in `handler.go`):

```go
// ListTemplates handles GET /app-templates — the built-in onboarding catalog.
func (h *Handler) ListTemplates(c *gin.Context) {
	response.OK(c, ToTemplateListItems(Templates()))
}

// GetTemplate handles GET /app-templates/:key — full template detail.
func (h *Handler) GetTemplate(c *gin.Context) {
	tpl, err := GetTemplate(c.Param("key"))
	if err != nil {
		response.NotFound(c, 40401, "template not found")
		return
	}
	response.OK(c, tpl)
}
```

- [ ] **Step 6: Verify build + full package tests**

Run: `go build ./... && go test ./internal/domain/app/ -v`
Expected: build OK; all app tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/domain/app/template_response.go internal/domain/app/template_response_test.go internal/domain/app/handler.go
git commit -m "feat(app): expose app-template catalog over console API"
```

---

### Task 4: Shared types + API client

**Files:**
- Modify: `web/packages/shared/src/types/index.ts`
- Modify: `web/packages/shared/src/api/app.ts`

**Interfaces:**
- Consumes: backend JSON shapes from Task 3.
- Produces:
  - `AppTemplateField`, `AppTemplate`, `AppTemplateListItem` types
  - `appApi.listTemplates(): Promise<AppTemplateListItem[]>`
  - `appApi.getTemplate(key: string): Promise<AppTemplate>`

- [ ] **Step 1: Add types**

Append to `web/packages/shared/src/types/index.ts`:

```typescript
export interface AppTemplateField {
  key: string
  label: string
  type: 'text' | 'textarea'
  placeholder?: string
  required?: boolean
  target: string // "redirect_uris" | "home_url" | "protocol_config.<name>"
}

export interface AppTemplateListItem {
  key: string
  name: string
  icon?: string
  category: string
  protocol: string
  description?: string
}

export interface AppTemplate extends AppTemplateListItem {
  client_type: string
  subject_strategy?: string
  doc_md?: string
  defaults?: Record<string, unknown>
  fields?: AppTemplateField[]
}
```

- [ ] **Step 2: Add API methods**

In `web/packages/shared/src/api/app.ts`, add to the `appApi` object (after `quickstart`), and ensure the new types are imported at the top of the file:

```typescript
  listTemplates: () =>
    client.get<ApiResponse<AppTemplateListItem[]>>('/app-templates').then(r => r.data.data),
  getTemplate: (key: string) =>
    client.get<ApiResponse<AppTemplate>>(`/app-templates/${key}`).then(r => r.data.data),
```

Add to that file's type import (the line importing `App`, `PaginatedData`, etc.):

```typescript
import type { AppTemplate, AppTemplateListItem } from '../types'
```

> If `app.ts` already imports from `../types`, extend that import instead of adding a second one.

- [ ] **Step 3: Verify typecheck**

Run: `pnpm -C web/apps/console exec tsc --noEmit`
Expected: exit 0, no errors.

- [ ] **Step 4: Commit**

```bash
git add web/packages/shared/src/types/index.ts web/packages/shared/src/api/app.ts
git commit -m "feat(shared): add app-template types and api client"
```

---

### Task 5: Console create-flow template picker

**Files:**
- Modify: `web/apps/console/src/pages/apps/index.tsx`
- Modify: `web/packages/shared/src/i18n/locales/en-US.ts`
- Modify: `web/packages/shared/src/i18n/locales/zh-CN.ts`

**Interfaces:**
- Consumes: `appApi.listTemplates`, `appApi.getTemplate`, `AppTemplate`, `AppTemplateListItem` (Task 4); existing `createForm` state and `handleCreate` in `apps/index.tsx`.
- Produces: a template-picker step that pre-fills `createForm` and a `templateState` carrying `defaults` + `fields` so submit merges them into `protocol_config`.

> No frontend test runner exists — verify with `tsc --noEmit` + the manual check in Step 5.

- [ ] **Step 1: Add picker state + loaders**

Near the other `useState` hooks in the apps component, add:

```typescript
const [templates, setTemplates] = useState<AppTemplateListItem[]>([])
const [activeTemplate, setActiveTemplate] = useState<AppTemplate | null>(null)
// field key -> value, for the template's differential inputs
const [tplFieldValues, setTplFieldValues] = useState<Record<string, string>>({})
```

Import the types/api at the top (extend the existing `@mxid/shared` import):

```typescript
import { appApi, protocolLabel, statusLabel, statusColor, cn, AppIcon, useTranslation } from '@mxid/shared'
import type { App, PaginatedData, AppTemplate, AppTemplateListItem } from '@mxid/shared'
```

When the create modal opens, load the catalog (add to the handler that opens the create modal, or a `useEffect` keyed on the modal-open boolean):

```typescript
useEffect(() => {
  if (!showCreate) return
  appApi.listTemplates().then(setTemplates).catch(() => setTemplates([]))
}, [showCreate])
```

> Use the actual create-modal visibility state variable in this file (e.g. `showCreate` / `createOpen`). Match the existing name.

- [ ] **Step 2: Add the template-select handler**

```typescript
const handlePickTemplate = useCallback(async (key: string) => {
  try {
    const tpl = await appApi.getTemplate(key)
    setActiveTemplate(tpl)
    setTplFieldValues({})
    setCreateForm((f) => ({
      ...f,
      protocol: tpl.protocol,
      client_type: tpl.client_type,
      // name/code stay user-entered; suggest name if empty
      name: f.name || tpl.name,
    }))
  } catch {
    toast.error(t('apps.templates.loadFailed'))
  }
}, [t])

const handleClearTemplate = useCallback(() => {
  setActiveTemplate(null)
  setTplFieldValues({})
}, [])
```

- [ ] **Step 3: Render the picker + dynamic fields**

At the top of the create modal body, before the existing manual fields, render the catalog when no template is chosen, and the doc + differential fields when one is:

```tsx
{!activeTemplate ? (
  <div className="space-y-3">
    <div className="text-sm font-medium text-gray-700">{t('apps.templates.pick')}</div>
    <div className="grid grid-cols-2 gap-2 max-h-64 overflow-y-auto">
      {templates.map((tpl) => (
        <button
          key={tpl.key}
          type="button"
          onClick={() => handlePickTemplate(tpl.key)}
          className="flex items-center gap-2 rounded-lg border border-gray-200 px-3 py-2 text-left hover:border-blue-400"
        >
          <AppIcon name={tpl.name} icon={tpl.icon} className="h-6 w-6" />
          <div>
            <div className="text-sm font-medium">{tpl.name}</div>
            <div className="text-xs text-gray-400">{protocolLabel(tpl.protocol)}</div>
          </div>
        </button>
      ))}
    </div>
    <button type="button" onClick={() => setActiveTemplate({ key: '', name: '', category: '', protocol: createForm.protocol, client_type: createForm.client_type } as AppTemplate)} className="text-sm text-blue-600">
      {t('apps.templates.blank')}
    </button>
  </div>
) : (
  <div className="space-y-4">
    {activeTemplate.key && (
      <div className="flex items-center justify-between rounded-lg bg-blue-50 px-3 py-2">
        <span className="text-sm font-medium text-blue-800">{activeTemplate.name}</span>
        <button type="button" onClick={handleClearTemplate} className="text-xs text-blue-600">{t('apps.templates.change')}</button>
      </div>
    )}
    {activeTemplate.doc_md && (
      <pre className="whitespace-pre-wrap rounded-lg bg-gray-50 px-3 py-2 text-xs text-gray-600">{activeTemplate.doc_md}</pre>
    )}
    {(activeTemplate.fields ?? []).map((fld) => (
      <div key={fld.key}>
        <label className="mb-1 block text-sm font-medium text-gray-700">{fld.label}</label>
        {fld.type === 'textarea' ? (
          <textarea className={inputCls} placeholder={fld.placeholder} value={tplFieldValues[fld.key] ?? ''}
            onChange={(e) => setTplFieldValues((v) => ({ ...v, [fld.key]: e.target.value }))} />
        ) : (
          <input className={inputCls} placeholder={fld.placeholder} value={tplFieldValues[fld.key] ?? ''}
            onChange={(e) => setTplFieldValues((v) => ({ ...v, [fld.key]: e.target.value }))} />
        )}
      </div>
    ))}
    {/* existing Name / Code fields stay below this block */}
  </div>
)}
```

> Keep the existing Name and Code inputs visible (they are always required). When `activeTemplate` is set, hide the manual Protocol/ClientType selects and the raw redirect_uris textarea — those now come from the template.

- [ ] **Step 4: Merge template values into the submit payload**

In `handleCreate`, before building the request body, fold the template into `protocol_config` / `redirect_uris`:

```typescript
// Build protocol_config + top-level fields from the active template (if any).
let protocolConfig: Record<string, unknown> = activeTemplate?.defaults ? { ...activeTemplate.defaults } : {}
let redirectUris: string[] = createForm.redirect_uris.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
let homeUrl = createForm.home_url

for (const fld of activeTemplate?.fields ?? []) {
  const raw = (tplFieldValues[fld.key] ?? '').trim()
  if (fld.required && !raw) {
    toast.error(t('apps.templates.fieldRequired', { label: fld.label }))
    return
  }
  if (!raw) continue
  if (fld.target === 'redirect_uris') {
    redirectUris = raw.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
  } else if (fld.target === 'home_url') {
    homeUrl = raw
  } else if (fld.target.startsWith('protocol_config.')) {
    const k = fld.target.slice('protocol_config.'.length)
    // service_urls is a CSV list; everything else passes through as a string
    protocolConfig[k] = k.endsWith('_urls')
      ? raw.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
      : raw
  }
}
```

Then use `protocolConfig`, `redirectUris`, `homeUrl`, plus `createForm.protocol` / `createForm.client_type` (already set from the template) when calling `appApi.create(...)`. When `activeTemplate` is null, fall back to the existing OIDC-default `protocol_config` builder already in `handleCreate`.

After a successful create, reset picker state alongside the existing form reset:

```typescript
setActiveTemplate(null)
setTplFieldValues({})
```

- [ ] **Step 5: Add i18n strings + verify**

Add to both locale files under the `apps` namespace (next to the existing `apps.createModal` block). English (`en-US.ts`):

```typescript
templates: {
  pick: 'Start from a template',
  blank: 'Or start from blank',
  change: 'Change template',
  loadFailed: 'Failed to load template',
  fieldRequired: '{{label}} is required',
},
```

Chinese (`zh-CN.ts`):

```typescript
templates: {
  pick: '从模板开始',
  blank: '或空白创建',
  change: '更换模板',
  loadFailed: '加载模板失败',
  fieldRequired: '{{label}} 不能为空',
},
```

Run: `pnpm -C web/apps/console exec tsc --noEmit`
Expected: exit 0.

Manual check: `make dev-docker-up`, open console → Apps → Create. Confirm: catalog shows ≥9 templates; picking "JumpServer" sets protocol to CAS and shows the Service URL field + doc; "Or start from blank" restores the manual form; creating a Feishu app succeeds with a `toast.success` and the new app shows protocol OIDC.

- [ ] **Step 6: Commit**

```bash
git add web/apps/console/src/pages/apps/index.tsx web/packages/shared/src/i18n/locales/en-US.ts web/packages/shared/src/i18n/locales/zh-CN.ts
git commit -m "feat(console): add template picker to app create flow"
```

---

### Task 6: Docs + edition note

**Files:**
- Modify: `docs/EDITIONS.md`

**Interfaces:**
- Consumes: nothing.
- Produces: a documented statement that the template marketplace is CE.

- [ ] **Step 1: Add the CE note**

In `docs/EDITIONS.md`, in the CE feature list (or a "Both editions" section), add:

```markdown
- **App template marketplace** (CE): create apps from built-in onboarding
  presets (Feishu, DingTalk, WeCom, GitLab, Grafana, Jenkins, Jira,
  Confluence, JumpServer). Templates are declarative and contain no secrets;
  template-created apps run the same validation as hand-filled ones.
```

- [ ] **Step 2: Verify full build + tests**

Run: `go build ./... && go test ./internal/domain/app/ && pnpm -C web/apps/console exec tsc --noEmit`
Expected: all green.

- [ ] **Step 3: Commit**

```bash
git add docs/EDITIONS.md
git commit -m "docs(editions): note app template marketplace is CE"
```

---

## Self-Review

**Spec coverage:**
- Built-in templates as embedded JSON → Task 1 (loader) + Task 2 (catalog). ✅
- No-secret discipline → Task 1 `secretLikeKeys` validation. ✅
- List/detail endpoints reusing `app.read` authz → Task 3. ✅
- Reuse existing `POST /apps` (no fork) → Task 5 Step 4 merges into the existing `handleCreate`. ✅
- Confluence + JumpServer included; JumpServer = CAS + `subject_strategy=username` → Task 2 + `TestJumpServerIsCAS`. ✅
- Protocol coverage oidc/saml/cas → `TestCatalogCoverage`. ✅
- toast feedback + `@mxid/shared` primitives + bilingual i18n → Task 5. ✅
- CE (not license-gated) → no `RequireFeature` anywhere; documented in Task 6. ✅

**Placeholder scan:** No TBD/TODO; every code step shows full code; JSON files are complete. Frontend steps that can't be unit-tested (no runner) state the explicit `tsc --noEmit` + manual check instead of a fake test. ✅

**Type consistency:** `Template`/`TemplateField` (Go) ↔ `AppTemplate`/`AppTemplateField` (TS) field names match the JSON tags (`client_type`, `subject_strategy`, `doc_md`, `defaults`, `fields`, `target`). `ToTemplateListItems` ↔ `TemplateListItem` ↔ `AppTemplateListItem` consistent. `appApi.listTemplates`/`getTemplate` names used identically in Tasks 4 and 5. ✅

## Notes / Risks
- The `Template.Defaults` keys must match what each protocol's config validator accepts (OIDC `scopes`/`grant_types`/…, SAML `sp_entity_id`/`acs_url`/`name_id_format`, CAS `service_urls`/`ticket_ttl`). If a key is wrong the create call returns a 400 — caught by the manual check in Task 5 Step 5. Cross-check against `internal/protocol/{oidc,saml,cas}` config validation before finalizing each JSON.
- `service_urls` is treated as a CSV/newline list (`*_urls` heuristic in Task 5 Step 4). If other list-valued protocol_config keys are added later, extend that heuristic.
