# Jenkins 接入 MXID（OIDC）

Jenkins 通过 **OIDC** 接 MXID（**别用 CAS**：CAS 插件老旧、功能受限；OIDC 支持后台通道登出、groups 角色映射，且是标准流程）。

## 0. 前提

- MXID 后端已处理 `X-Forwarded-Proto` + `trusted_proxies`（见 [接入总览](README.md#部署前提接第一个应用前必看)）。否则第 3 步填 Discovery URL 时会报 `ParseException: Unexpected token <!doctype html>`（后端 403 返回了前端 HTML）或直接 403。
- Jenkins 有一个外部可达的 **HTTPS** 地址（下面记作 `<JENKINS>`，如 `https://ci.example.com`）。**Manage Jenkins → System → Jenkins URL 必须填这个外部 HTTPS 地址**，不能是 `localhost`——OIDC 回调按它拼。

## 1. 装插件

Manage Jenkins → Plugins → Available → 搜 **`oic-auth`** → 装 **OpenID Connect Authentication** → 重启。

> ⚠️ **别装错**。marketplace 里有三个名字像的：
> - ✅ **OpenID Connect Authentication**（`oic-auth`）——Jenkins 作为**客户端**登录 MXID，**就是这个**。
> - ❌ OpenID Connect Provider ——让 Jenkins 自己当 IdP 给别的应用发 token，方向反了。
> - ❌ OIDC Backchannel Logout ——上面 Provider 的配套，也是反的。
>
> 搜 "OIDC" 往往只出 Provider 系；请搜全名 `OpenID Connect Authentication` 或插件 id `oic-auth`。

## 2. MXID 侧建应用

MXID console 新建 OIDC 应用：

- **Redirect URI**：`<JENKINS>/securityRealm/finishLogin`
- **Scopes**：`openid profile email groups`
- **Claim mapper**（让 groups 进 token，必加）：`{"claim":"groups","source":"user.groups.codes"}`
- 记下生成的 **client_id** / **client_secret**

## 3. Jenkins 配 Security Realm

Manage Jenkins → Security → **Security Realm** 选 "Login with Openid Connect"。

推荐 **Automatic configuration**（自动发现）：

| 字段 | 值 |
|------|-----|
| Configuration mode | **Automatic** |
| Well-known configuration endpoint | `<HOST>/protocol/oidc/.well-known/openid-configuration` |
| Client id | 第 2 步的 client_id |
| Client secret | 第 2 步的 client_secret |
| Scopes | `openid profile email groups` |

**User fields**（claim 映射）：

| 字段 | 填 |
|------|-----|
| User name field | `preferred_username`（或 `sub`） |
| Full name field | `name` |
| Email field | `email` |
| Groups field | `groups` |

**Logout**（接 MXID 的下游强制登出）：

- ✅ Enable "Logout from OpenID Provider"（RP-initiated logout）
- Post logout redirect URL：`<JENKINS>/`
- end_session 端点自动发现，无需手填

## 4. 授权策略（用 groups 做角色）

Security → **Authorization** 选 **Matrix Authorization Strategy**（或 Role-based）：

- 加一个 group，**名字 = MXID `groups` claim 里吐出来的 code**（大小写敏感）。
- 勾对应权限（Overall/Read、Job/Build 等）。
- **先保留一个已知的本地 admin 账号**，防止配错锁死。

## 5. 验证

浏览器访问 `<JENKINS>` → 应跳到 MXID 登录页 → 登录（SP 发起会有一次「登录到 Jenkins？」确认页，正常）→ 跳回 Jenkins 并按 groups 拿到权限。

命令行先自测 Discovery 通不通：

```bash
curl -s <HOST>/protocol/oidc/.well-known/openid-configuration | head -c 100
# 期望：{"authorization_endpoint":"...","issuer":"<HOST>/protocol/oidc",...}
```

## 常见问题

| 现象 | 原因 / 解决 |
|------|-------------|
| 填 well-known 报 `ParseException: Unexpected token <!doctype html>` | 后端 403 把前端 HTML 返回了。边缘没把 `X-Forwarded-Proto: https` 传到后端 → issuer scheme 不匹配。见[前提](README.md#部署前提接第一个应用前必看)。 |
| discovery 直接 403 | 同上（scheme 不匹配），或 issuer host 跟访问 host 对不上。`curl -H "X-Forwarded-Proto: https" ...` 能通就是这个。 |
| 登录后 0 权限 | Matrix 里的 group 名跟 MXID `groups` claim 值不一致（大小写/拼写），或应用没加 groups claim mapper → token 里没 groups。 |
| 锁死进不去 | 改 `JENKINS_HOME/config.xml` 把 `useSecurity` 设 false 重启回滚；所以第 4 步要留本地 admin。 |
| 想要 refresh token | 加 `offline_access` scope（一般 Jenkins 不需要）。 |

## 说明

- MXID 的 `client_secret_jwt`（HS256）**不支持**——若要 JWT 客户端认证用 `private_key_jwt`。Jenkins oic-auth 默认 `client_secret_basic`，够用。
- 离职/JIT 到期时，MXID 会通过 OIDC **后台通道登出**主动踢掉 Jenkins 会话（需上面第 3 步的 logout 开着）。
