# 应用接入总览

MXID 支持三种 SSO 协议：**OIDC / SAML / CAS**。本目录是各应用的接入手册。

## OIDC（推荐）

OIDC 引擎基于 [`zitadel/oidc`](https://github.com/zitadel/oidc) v3，是标准、维护活跃的 OpenID Connect Provider。**优先用 OIDC**（比 SAML/CAS 更现代、配置更简单、支持后台通道登出）。

### 关键端点

以 `https://<你的域名>`（即 issuer 根，下面记作 `<HOST>`）为例：

| 名称 | 地址 |
|------|------|
| **Discovery** | `<HOST>/protocol/oidc/.well-known/openid-configuration` |
| **issuer (`iss`)** | `<HOST>/protocol/oidc` ← 注意带 `/protocol/oidc` 后缀 |
| authorization | `<HOST>/protocol/oidc/authorize` |
| token | `<HOST>/protocol/oidc/token` |
| userinfo | `<HOST>/protocol/oidc/userinfo` |
| jwks | `<HOST>/protocol/oidc/jwks` |
| end_session（登出） | `<HOST>/protocol/oidc/end-session` |
| revocation / introspection | `<HOST>/protocol/oidc/revoke` · `/introspect` |

> **接入时优先填 Discovery URL**（自动发现），不要手填各端点——省事且不会填错。绝大多数客户端只需要 Discovery URL + client_id + client_secret。

### 能力矩阵（当前引擎）

| 项 | 支持情况 |
|----|----------|
| response_type | **仅 `code`**（授权码 + PKCE S256）。implicit 已弃用（OAuth 2.1） |
| grant_type | `authorization_code`、`refresh_token`、`client_credentials`（机器对机器） |
| 客户端认证 | `client_secret_basic`、`client_secret_post`、`private_key_jwt`、`none`(公有客户端+PKCE) |
| **不支持** | `client_secret_jwt`（HS256）—— 密钥单向 bcrypt 存储，无法 HMAC；请用 `private_key_jwt` |
| refresh token | 需请求 **`offline_access`** scope 才会签发 |
| 后台通道登出 | 支持（`backchannel_logout_supported`）——离职/JIT 到期会强制登出下游应用 |

### 常用 scope 与 claim

- **scope**：`openid profile email groups`（`offline_access` 换 refresh token）
- **id_token / userinfo 里的 claim**：
  - `sub`：主体标识（默认策略 = 用户名；可在应用里改 subject 策略为 pairwise/persistent_id/email）
  - `groups`：用户所属组的 code 列表 —— **需要应用配置里加 `groups` claim mapper**
  - `app_roles`：用户在**本应用**的角色 code 列表（给 RP 直接做角色映射，比解析 groups 省事）
  - `tenant_code`、`preferred_username`、`email` / `email_verified`、`name`、`amr`、`sid`

> 要让 `groups` 出现在 token，需在 MXID console 的应用配置里加 claim mapper：
> `{"claim":"groups","source":"user.groups.codes"}`

### 登录确认行为

- **SP 发起**（第三方应用把用户跳转过来）：每次登录都会显示一次「登录到 App X？」确认页（Google 风格）。
- **IdP 发起**（用户从 MXID 门户点应用图标进）：无感直登。

## 部署前提（**接第一个应用前必看**）

MXID 后端在 TLS 边缘（GKE Gateway / nginx / LB）后面时，有两个坑必须先处理，否则 OIDC 会 403 / 用户会莫名 429：

1. **`X-Forwarded-Proto: https` 必须传到后端。** TLS 在边缘卸载后，后端收到的是明文 http；zitadel 引擎会拿它跟 https 的 issuer 比对，不匹配就 **403**（discovery/authorize 全挂）。
   - GKE Gateway API：在 HTTPRoute 的后端路由加 `RequestHeaderModifier` set `X-Forwarded-Proto: https`（Helm 值 `routing.forwardedProtoHttps`）。
   - nginx：`location /protocol/` 里显式 `proxy_set_header X-Forwarded-Proto $scheme;`（一旦 location 内设了任何 proxy_set_header，继承的头会全丢，要重新声明）。
2. **配 `trusted_proxies`**（Helm 值 `config.trustedProxies`）。不配的话所有客户端的真实 IP 被压扁成 LB 的一个 IP，共用一个限流桶 → 整个办公室/集群一起 **429**。GKE 抄 `130.211.0.0/22`、`35.191.0.0/16` + 你的 Pod CIDR。

## 各应用接入手册

- [Jenkins（OIDC）](jenkins-oidc.md)
- Grafana（OIDC）：demo 见 `~/Workspaces/Docker/demo`（generic_oauth）
- JumpServer：仅社区版 **CAS**（见 [[reference_app_protocol_support]] 备注）

## SAML / CAS

SAML、CAS 引擎按**应用分段**挂载：

- SAML metadata：`<HOST>/protocol/saml/<app>/metadata`
- CAS：`<HOST>/protocol/cas/<app>/login`、`/serviceValidate`

（裸 `/protocol/saml/metadata`、`/protocol/cas/login` 会 404 —— 必须带应用标识段。）
