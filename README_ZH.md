<div align="center">

# MXID

**开源 · 多协议 · 企业级身份与访问管理(IAM / SSO)平台**

一个登录门户、一个管理控制台、一套协议网关 —— 覆盖 **OIDC**、**SAML 2.0**、
**CAS 3.0**、**JWT**,让企业内所有应用接入同一身份层。

[![License](https://img.shields.io/badge/Core-AGPL_v3.0-blue.svg)](LICENSE)
[![Enterprise](https://img.shields.io/badge/Enterprise-Commercial-8A2BE2.svg)](docs/EDITIONS.md)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7+-DC382D?logo=redis&logoColor=white)](https://redis.io)
<br/>
[![Release](https://img.shields.io/github/v/release/imkerbos/mxid?include_prereleases&sort=semver)](https://github.com/imkerbos/mxid/releases)
[![Stars](https://img.shields.io/github/stars/imkerbos/mxid?style=flat&logo=github)](https://github.com/imkerbos/mxid/stargazers)
[![Issues](https://img.shields.io/github/issues/imkerbos/mxid)](https://github.com/imkerbos/mxid/issues)
[![Last commit](https://img.shields.io/github/last-commit/imkerbos/mxid)](https://github.com/imkerbos/mxid/commits)

[English](README.md) · **简体中文**

</div>

---

MXID 是自托管、单租户的企业级 IAM 平台,面向商业级部署设计 —— 支持多语言,对标
Keycloak / Auth0 / Okta / TopIAM。采用**开源核心(open core)**:社区版完整可用、
AGPL 授权;企业版通过签名 license 解锁外部 IdP 登录、品牌定制等。

> **v1.4.1** —— 最新稳定版。更新日志见 [releases](https://github.com/imkerbos/mxid/releases)。:tada:

<div align="center">

![MXID 门户 —— 一个入口聚合所有应用,覆盖 OIDC / SAML / CAS / 表单填充](docs/screenshots/portal-apps.png)

</div>

## 功能亮点

- **协议开箱即用** —— OpenID Connect 1.0(基于 OAuth 2.0;PKCE / Refresh / RP-Initiated Logout)、SAML 2.0(IdP/SP 发起、SLO)、CAS 3.0、JWT。支持按应用配置 claim / attribute 映射。
- **认证** —— 密码策略(强度 / 历史 / 锁定 / 验证码)、TOTP MFA + 恢复码、邮件魔法链接、外部 IdP 登录(企业版)。
- **身份与访问** —— 用户、组织、组、RBAC;按应用的访问策略与角色,角色作为 claim 下发。
- **表单填充 SSO(SWA)** —— 接入只有账号密码表单、不支持标准协议的老旧 Web 系统。MXID 托管下游凭证,加固的 MV3 浏览器扩展自动填充并提交应用自己的登录表单。支持按用户 / 共享凭证、录制即配置、reveal 受 step-up + 令牌绑定保护(企业版)。
- **改配置不重启** —— SMTP、安全策略、品牌、登录方式、协议默认值、对外 URL 全部在控制台运行时可改。
- **运维** —— 审计日志 + 留存 + 告警 webhook、API Token(OpenAPI)、中英双语。
- **生产级交付** —— 单二进制后端 + 容器化边缘;tag 驱动多架构镜像;Ed25519 签名离线授权。
- **无状态后端 / Kubernetes 友好** —— 图标与品牌 logo 以 `bytea` 存入 PostgreSQL(≤ 2 MB,强缓存 ETag),后端无任何本地磁盘状态,无需 PVC,容器重启不丢失,多副本即开即一致。
- **如实公布能力** —— `/system/info` 只上报当前二进制实际具备的功能:runtime 门控功能(`branding`、`conditional_access`,代码在 CE 内,license 放行即生效)与代码分离的 EE-only 功能(`external_idp` 等,仅 EE 二进制含其码)明确区分,客户端不会收到虚假的能力声明。

## 架构

```
                       ┌────────────────────────────────┐
                       │            终端用户             │
                       └───────────────┬────────────────┘
                                       ▼
                       ┌────────────────────────────────┐
                       │   门户 SPA (Vite + React)       │
                       │   /login  /consent  /apps       │
                       └───────────────┬────────────────┘
                                       │ session cookie
        ┌──────────────────────────────▼─────────────────────────────┐
        │                    MXID 后端 (Go)                           │
        │  ┌────────────────┐ ┌───────────────┐ ┌──────────────────┐ │
        │  │ 协议网关       │ │ 认证引擎      │ │ 设置域           │ │
        │  │ OIDC/SAML/CAS  │ │ 密码+TOTP     │ │ 热加载(SMTP/    │ │
        │  │ JWT            │ │ +外部 IdP     │ │ 品牌/策略)       │ │
        │  └───────┬────────┘ └───────┬───────┘ └──────────────────┘ │
        │          └────────┬─────────┘                              │
        │          ┌────────▼─────────┐  ┌──────────────────┐        │
        │          │ 身份解析         │  │ 访问 / 角色      │        │
        │          │ user/group/org   │  │ 按应用策略       │        │
        │          └────────┬─────────┘  └────────┬─────────┘        │
        │     ┌─────────────▼─────────────────────▼────────────┐     │
        │     │  控制台 SPA(管理)— /users /apps /orgs        │     │
        │     └─────────────────────────────────────────────────┘    │
        └──────────────────────────────┬─────────────────────────────┘
                  ┌────────────────────┼────────────────────┐
                  ▼                    ▼                    ▼
        ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
        │   PostgreSQL     │ │      Redis       │ │   SMTP / SMS     │
        │ 租户/用户/       │ │ 会话/票据/       │ │   服务商         │
        │ 应用/审计 ...    │ │ 事件             │ │                  │
        └──────────────────┘ └──────────────────┘ └──────────────────┘
                  ▲
                  └─────── 外部 SP:Grafana · JumpServer · Jira · Harbor · …
```

Go 后端(Gin + GORM + Redis + 雪花 ID)。React 19 + Vite + TypeScript + Tailwind
(pnpm 工作区:`console`、`portal`、`shared`)。PostgreSQL 主存储;Redis 负责
会话 / 票据 / TOTP 限流 / 事件 SSE。

## 快速开始(开发环境)

```bash
git clone https://github.com/imkerbos/mxid.git
cd mxid
cp .env.example .env
make dev-docker-up          # 后端 + 控制台 + 门户 + air 热重载
```

开发环境跑在 dev nginx 的 **3500 端口**(热重载,**非生产**):

| 入口 | 地址 |
|------|------|
| 门户(终端用户) | <http://localhost:3500/> |
| 控制台(管理) | <http://localhost:3500/admin/> — 默认 `admin` / `admin123` |
| 接口 | <http://localhost:3500/api/v1/...> |
| OIDC 发现 | <http://localhost:3500/protocol/oidc/.well-known/openid-configuration> |

**生产环境**是另一套:拉发布镜像,经 nginx 跑在 **80 / 443**(TLS),用
`docker compose` 启动。路径一致,只是 host 和端口不同:

```bash
make prod-docker-up         # 生产编排(发布镜像,TLS 就绪)
```

后端完全无状态 —— 品牌资源存储在数据库中,水平扩展和 Kubernetes 部署无需共享卷。
详见 **[docs/DEPLOYMENT_ZH.md](docs/DEPLOYMENT_ZH.md)**(中文部署文档);架构设计见
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 版本(CE / EE)

MXID 采用**开源核心**。社区版免费、完整可用;企业版通过 Ed25519 签名离线 license
解锁更多功能,在控制台激活(无需重启)。完整矩阵、架构、激活与限制见
**[docs/EDITIONS.md](docs/EDITIONS.md)**。

### 功能对比

| 功能 | 社区版 | 企业版 |
|------|:---:|:---:|
| **协议** | | |
| OpenID Connect 1.0 / OAuth 2.0(PKCE / Refresh / RP-Initiated Logout) | ✅ | ✅ |
| SAML 2.0(IdP/SP 发起、SLO) | ✅ | ✅ |
| CAS 3.0 | ✅ | ✅ |
| JWT(HS256 / RS256) | ✅ | ✅ |
| **认证** | | |
| 密码登录 + 策略(强度 / 历史 / 锁定 / 验证码) | ✅ | ✅ |
| TOTP MFA + 恢复码 | ✅ | ✅ |
| 邮件魔法链接(免密) | ✅ | ✅ |
| 外部 IdP 登录(Lark / 飞书 / Teams) | ❌ | ✅ |
| 短信 OTP 登录 | ❌ | ✅ |
| 条件访问 / 风险登录 | ❌ | ✅ |
| 高级 step-up(sudo 模式) | ❌ | ✅ |
| WebAuthn / Passkey | ❌ | ✅ ¹ |
| **身份与访问** | | |
| 用户 | ✅ 上限 100 | ✅ 不限 |
| 组织 / 组 | ✅ | ✅ |
| RBAC(角色 + 权限) | ✅ | ✅ |
| SCIM 2.0 自动同步 | ❌ | ✅ ¹ |
| **应用与 SSO** | | |
| 应用注册(OIDC / SAML / CAS / JWT) | ✅ 不限 | ✅ 不限 |
| 按应用访问策略(用户 / 组 / 组织 / 角色) | ✅ | ✅ |
| 按应用角色 → claim | ✅ | ✅ |
| API Token(OpenAPI) | ✅ | ✅ |
| 表单填充 SSO(SWA)—— 浏览器扩展为纯账密 Web 系统自动登录 | ❌ | ✅ |
| **运维** | | |
| 审计日志 + 留存 + 告警 webhook | ✅ | ✅ |
| SMTP 邮件 + 模板 | ✅ | ✅ |
| 中英双语 | ✅ | ✅ |
| 品牌定制 / 白标(logo、主色、登录页) | ❌ | ✅ |

¹ 规划中。

> license 过期后**优雅降级到社区版上限** —— 登录照常、已有数据全保留,仅"新建超过
> CE 上限"被拦,续期即恢复。

## 集成(已实战验证)

控制台内置集成指南,见 `/admin/docs`:

| 应用 | 协议 | 状态 |
|------|------|------|
| Grafana | OIDC | ✅ `groups` claim → `role_attribute_path` |
| JumpServer v4 | CAS 3.0 | ✅ 用户自动创建、属性同步 |
| Harbor / Gitea / Jira / Confluence / Jenkins / AWS / Lark | OIDC / SAML / CAS | 见 `/admin/docs` |

## 表单填充 SSO(浏览器扩展)

不是每个内部系统都支持 OIDC / SAML / CAS。对于只有账号密码表单的老旧 Web 系统,
MXID 提供**表单填充 SSO**(即 SWA —— Secure Web Authentication):下游凭证托管在
MXID,由 **MXID Login** 浏览器扩展把它填进应用**自己的**登录表单。MXID 全程不与
应用直接通信,填充时密码也不离开浏览器。

![自动填充实况 —— 扩展填好并提交应用的登录表单](docs/screenshots/formfill-autofill.png)

**工作原理**

1. 管理员以 **表单填充** 协议注册应用 —— 填登录 URL + 字段选择器,或让扩展
   **录制**一次真实登录自动生成。
2. 用户安装 **MXID Login** 扩展(Chrome / Edge,Manifest V3)。纯内网环境通过
   企业策略 + 自托管 CRX 下发,**无需 Chrome 应用商店**。
3. 凭证支持**按用户**(每人托管自己的)或**共享**(管理员设一份给所有人),
   两种模式可按应用共存。
4. 打开应用登录页 → 扩展 reveal 凭证并自动填充 + 提交。reveal 受门户会话
   **+ 令牌绑定的每安装密钥 + step-up MFA + 应用访问策略**多重保护,且每次
   reveal 都记审计。

<p align="center"><img src="docs/screenshots/extension-popup.png" width="340" alt="MXID Login 扩展弹窗 —— 按应用填充状态与一键录制"></p>

**一步到位** —— 扩展的 *Record login*(录制登录)一次同时抓取字段选择器**并**存下
凭证,用户对着应用登录一次即完成接入。不想托管密码的用户直接跳过即可:应用降级为
普通启动入口,手动输入密码。

设计与安全:[表单填充设计](docs/FORM-FILL-SSO-DESIGN.md) ·
[安全规格](docs/FORM-FILL-SSO-B0-SECURITY-SPEC.md) ·
[扩展令牌绑定](docs/FORM-FILL-EXTENSION-TOKEN-BINDING.md)。

## 项目结构

```
mxid/
├── cmd/server/        # thin main → app.Run()(CE 入口)
├── app/               # 服务装配(可导入;EE 复用 app.Run)
├── internal/
│   ├── bootstrap/     # 配置、路由、app 壳
│   ├── domain/        # user / app / tenant / org / group / permission / authn / audit / setting / ...
│   ├── protocol/      # OIDC / SAML / CAS 处理器
│   ├── gateway/       # console(管理 REST)+ portal(终端 REST)
│   └── middleware/    # cors、logger、request-id、feature gate
├── pkg/
│   └── ee/            # license(Ed25519 验签)+ registry(EE 扩展点)
├── migrations/        # SQL
├── web/               # console + portal + shared(React,pnpm 工作区)
├── deploy/            # compose / dockerfile / nginx
└── docs/              # DEPLOYMENT / EDITIONS / ARCHITECTURE
```

## Star 趋势

[![Star History Chart](https://api.star-history.com/svg?repos=imkerbos/mxid&type=Date)](https://star-history.com/#imkerbos/mxid&Date)

## 参与贡献

- [CONTRIBUTING.md](CONTRIBUTING.md) —— 开发环境、分支与提交规范、lint/test 流程。
- [SECURITY.md](SECURITY.md) —— 漏洞报告。
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
- Bug / 需求:[GitHub Issues](https://github.com/imkerbos/mxid/issues)。

## 许可

版权所有 © 2026 **MatrixPlus**。MXID 采用**开源核心**:

- **社区版**(本仓库)—— **GNU Affero 通用公共许可证 v3.0**([LICENSE](LICENSE))。把修改后的 MXID 作为网络服务对外提供时,必须以相同许可公开你的修改。
- **企业版** —— `mxid-ee` 发行版及 EE 门控功能受**商业许可**约束([LICENSE.EE](LICENSE.EE)),见 [docs/EDITIONS.md](docs/EDITIONS.md)。
