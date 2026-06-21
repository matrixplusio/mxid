# Phase 1 深度方案 — 接入与生命周期

> 范围:P1.1 应用接入模板市场、P1.2 出站供应/SCIM push。
> 三轴评估:① CIAM/EIAM 最佳实践 ② 项目要求(CLAUDE.md)③ 企业最佳实践。
> 基于代码实证(已核 app model / event bus / safehttp / crypto.Secret / EE seam)。

---

## 0. 实证基线(已验证)

| 设施 | 现状 | 对方案的影响 |
|------|------|-------------|
| App 模型 | `ProtocolConfig` / `RedirectURIs` 均 JSONB,无模板概念 | 模板天然契合,加表即可 |
| 事件总线 `pkg/event/bus.go` | **内存版**,goroutine-per-handler,panic-safe,**无持久化** | ⚠️ 供应不能直接挂总线,崩溃丢事件 |
| Job queue | **无**;mailer 同步阻塞 handler | ⚠️ 供应需自建 outbox + worker |
| `pkg/safehttp` | SSRF 防护齐全,每跳重检 IP | 出站直接复用,符合 CLAUDE.md 强制项 |
| `pkg/crypto.Secret` | KEK 加密,DB 透明加解密,API 返回 `********` | 下游凭证直接复用 |
| EE seam `pkg/ee/registry` | `RegisterInit`/`RegisterConsole`/`MarkFeature` | 供应走 EE 隔离注册 |
| SCIM | 仅 feature key `scim`,**零实现** | 全新实现,在 mxid-ee |
| 审计 | 订阅 ~40 事件自动留痕 | 供应动作自动可审计 |
| 迁移 | `NNNNN_*.up/down.sql`,下一个 `000042` | — |

---

## P1.1 应用接入模板市场

### 定位
对标 Okta Integration Network (OIN) / MaxKey 模板库。把"手填 6+ 字段"降为"选模板 + 填 2-3 个差异字段"。**纯 CE**(降门槛是装机量杠杆)。

### 三轴评估
- **CIAM 最佳实践 ✅**:模板 = 声明式集成预设,业界标准做法。关键纪律:**模板绝不含密钥**,只含协议默认值 + 占位符 + 接入文档。
- **项目要求 ✅**:模板创建仍走现有 `CreateAppRequest` 校验路径(scope/subject_strategy 配对、code 唯一),不绕过 authz `app.create`、不绕过审计。
- **企业最佳实践 ✅**:内置模板随版本走(可审计、可回滚);企业私有模板单独治理。

### 架构
**双源模型**(hybrid):
1. **内置模板** — 仓库内 `internal/domain/app/templates/*.json`,`go:embed` 进二进制。版本化、随发布、CE 全量。
   ```jsonc
   // templates/feishu-oidc.json
   {
     "key": "feishu-oidc", "name": "飞书", "icon": "...",
     "protocol": "oidc", "client_type": "web_app",
     "category": "collaboration",
     "doc_md": "1. 在飞书开放平台创建应用…",
     "defaults": {                        // 注入 ProtocolConfig
       "scopes": ["openid","profile","email"],
       "grant_types": ["authorization_code"],
       "pkce_required": true
     },
     "fields": [                          // 向导只问差异字段
       {"key":"redirect_uris","label":"回调地址","required":true}
     ]
   }
   ```
2. **私有模板**(可选,后置/EE)— `mxid_app_template` 表,租户自建/导入。本期**不做表**,只做内置 JSON,降复杂度。

**后端**:
- `internal/domain/app/template.go`:`LoadTemplates()`(embed 解析 + 校验)、`GetTemplate(key)`。
- 新路由(console,gate `app.read`/`app.create`):
  - `GET /api/v1/console/app-templates` — 列表(key/name/icon/category/protocol)。
  - `GET /api/v1/console/app-templates/:key` — 详情(含 doc_md + fields)。
  - 创建复用现有 `POST /api/v1/console/apps`:前端把 `template.defaults` 合并进 `protocol_config` 后提交。**不新增创建端点**(避免校验分叉)。

**前端** `web/apps/console/src/pages/apps/index.tsx`:
- 创建流前插一步"选模板 / 空白创建"。
- 选模板 → 预填表单 + 渲染 `doc_md` 侧栏 + 只显 `fields` 差异项。
- 写反馈走 `toast`(CLAUDE.md),原语用 `@mxid/shared`。

### 风险 / 纪律
- 模板 `defaults` 必须过与手填**同一套校验**(在 service 层,不在前端兜底)。
- 模板里禁出现任何 secret 字段;评审清单加一条。
- 图标:用现有 `000041_upload_blob` 或内置 data-uri,不外链(防 SSRF/失效)。

### 工作量
约 1.5-2 周。低风险。**先做**(无依赖,解锁接入体验)。

---

## P1.2 离职销户 / 访问回收(Offboarding & Access Revocation)

> **重大范围修正**(2026-06,基于实战反馈):
> 原方案"出站供应 = 入职自动开户"**不现实,已废弃**。
> 现实约束:下游 SaaS(如飞书)由客户 IT 维护,登录集成只拿到**读用户信息**权限,
> 拿不到写/管理员权限去建账号。硬做"自动开户"是不懂行。
> **本期只做离职销户/访问回收**,且按"管得着的程度"分三层,不假装能碰碰不到的系统。

### 定位
员工离职 → 切断其对所有 App 的访问。对标 Okta Offboarding:**能自动的自动,够不着的列报告交人**。

### 核心洞察:按"控制力"分三层

| 层 | App 类型 | 我们的控制力 | 处理方式 | 版本 |
|----|---------|-------------|---------|------|
| **L1** | 走 MXID SSO 登录(OIDC/SAML/CAS),无独立密码 | **100% 掌控** | 禁用用户 → 即时切断 SSO + 撤 token + back-channel logout | **CE** |
| **L2** | 客户 IT 授予了 SCIM/管理凭证的 App | 有写权限才有 | SCIM PATCH `active=false` 停用下游账号 | EE(可选连接器) |
| **L3** | 客户 IT 自管、无写权限(如飞书) | **碰不到** | 生成离职待办 + webhook 通知 IT/HR 系统,人去关 | CE(报告) |

**L1 是离职销户的 80%,全在掌控里,零下游权限依赖,价值最大风险最低 → 本期重点。**
**不要把 L3 硬做成自动化** —— 没权限就是没权限,列清单交人办才是工业级正解。

### L1 — SSO 访问切断(CE,本期重点)

**这是离职销户的主体,全在 MXID 掌控,不依赖任何下游权限。**

禁用/离职用户时,一键扇出:
1. **禁用账号** → 后续任何 SSO 鉴权直接拒。
2. **撤销所有活跃会话**(`pkg/session`,console/portal/protocol 三命名空间全清)。
3. **撤销所有 OIDC refresh/access token**(复用现有 `OIDCTokenRevoked` 路径)→ 防旧令牌续命。
4. **Back-channel logout 扇出** → 对每个参与的 App 推签名 logout_token(现有能力),让 App 立即踢人。
5. **CAS/SAML 单点登出** 一并触发。

→ 效果:人一离职,**所有走 MXID 登录的 App 瞬间全部进不去**,无需碰下游。

**实证基础**:back-channel logout、token revoke、session 三命名空间**均已存在**,本期只需把它们**编排成一个"离职/禁用"原子动作**(一个 service 方法 + 一个 console 按钮)。工程量小。

### L2 — 下游账号停用(EE,SCIM 连接器,**默认关闭**)

仅对**客户 IT 已授予写凭证**的 App。SCIM `PATCH active=false`(去激活非硬删,合规取证)。
- **per-app 开关,默认 OFF**(`provisioning_enabled=false`):即使配好连接器,管理员不显式打开就不会触下游。安全默认 —— 防误碰客户生产系统。
- 没给权限的 App(如飞书)不配连接器 → 自动落 L3,不强求。
- 连接器接口化 `Connector{ Deprovision(externalID) error }`,SCIM 通用实现优先;私有 API 适配按客户需求增量加。
- **触发可靠性**:L2 走**事务性 outbox**(下面),保证"禁用了但下游没停"不会悄悄漏掉。

### L3 — 离职待办报告(CE,**Console 待办 + Webhook 双轨**)

碰不到的 App(IT 自管、或 SCIM 未开):**不假装自动化**,但要让人/对方系统接得住。

**App footprint 来源**(离职时该用户关联哪些 App):
- 经 org/group 授权可访问的 App;∪
- 实际登录过的 App(复用现有 `AppLaunched` 事件记录)。

每个 App 自动判级:SSO→L1 必切;SCIM 已开→L2;否则→**L3**。

**双轨处理(都做):**
1. **Console 待办清单**:每个 L3 App 一行 offboarding item,状态 `待处理`。管理员去下游关完账号,回来点"已处理"(记 who/when,审计留痕)。一眼看出哪些没关完。
2. **Webhook 通知**:推 `offboarding.initiated` 给客户 IT/HR/ITSM,payload 带要关的 App 清单(HMAC 签名 + `pkg/safehttp` + outbox 重试)。对方系统自动开工单。
   - 下游关完可**回调**(`offboarding.item.done`)→ 自动勾掉对应 Console 待办;无回调则人工点。

→ 对标 Okta Deprovisioning Report:webhook 给机器对接,待办给人盯梢,互补不冲突。

### 触发可靠性:事务性 outbox(L1 扇出 + L2 推送共用)

现内存事件总线 = **at-most-once,进程崩丢事件**。离职这种安全动作**绝不能丢**(漏一个 = 离职账号还活着 = 安全事故)。

```
禁用用户 ──(同一 DB 事务)──┐
                          ├─ UPDATE mxid_user SET status=disabled
                          └─ INSERT mxid_offboarding_task(各 App 一条,pending)  ← 同事务,不丢
                                      │
worker(轮询):
  SELECT … WHERE status='pending' AND next_attempt<=now() FOR UPDATE SKIP LOCKED  ← 多副本安全
  → L1 任务:撤会话/token + back-channel logout(本地,几乎不失败)
  → L2 任务:safehttp 推下游 SCIM 停用(查 link 表幂等)
  → L3 任务:发 webhook / 生成待办
  → 成功 done / 失败退避重试 / 超限 → 死信 + 审计告警
```

要点:
1. **持久化**:任务与禁用动作同事务 → 不丢。
2. **幂等**:`mxid_offboarding_link(user_id, app_id, external_id)`,重试不重复。
3. **退避重试 + 死信告警**:下游超时不丢,补偿到成。
4. **多副本安全**:`FOR UPDATE SKIP LOCKED`,无 leader 选举,零新依赖。
5. **可观测**:console 离职面板(每 App 处理状态/重试/手动重试)。
6. **不引外部队列**:PG outbox + SKIP LOCKED 足够,符合「自建只做胶水」。

### 项目要求(CLAUDE.md)逐条 ✅
- 出站(L2 SCIM / L3 webhook)**全走 `pkg/safehttp`**(下游 URL 用户可填 → SSRF 强制)。
- 下游凭证 **`crypto.Secret` + KEK**,API 返回 `********`。
- console 写路由 `authz.Require` + `Protect`;离职动作高危 → **step-up MFA**。
- **每步审计** who/ip/when/what/result。
- L2 连接器 **EE 代码隔离 + garble**,`registry.RegisterInit` 注册;`license` 门控 `scim`。
- 多租户:配置 `TenantScoped`。

### 架构落点
- **L1**(CE):新 `internal/domain/offboarding/` —— 编排现有 session/token/back-channel logout 为原子动作 + console "一键离职"按钮。
- **outbox**(CE):`internal/domain/offboarding/outbox/`,task/item 表 + worker(`SKIP LOCKED` 轮询 + 退避)。
- **L2 连接器**(EE,mxid-ee):`provisioning/connector/scim/`,`Connector.Deprovision` 接口;per-app `provisioning_enabled` 默认 false;`license` 门控 `scim`。
- **L3**(CE):
  - 待办:`offboarding_item` 表 + console 离职面板(清单/状态/手动勾掉)。
  - webhook:`internal/domain/webhook/`(订阅地址配置 + HMAC 签名 + 投递走 outbox + 回调勾销)。
- 迁移:`000042_offboarding.up.sql`(task / item / link 表)、`000043_webhook.up.sql`(webhook 配置 + 投递记录)。

### 数据模型(草案)
- `mxid_offboarding_task`(user_id, tenant_id, status, created_by, created_at)—— 一次离职一行。
- `mxid_offboarding_item`(task_id, app_id, tier L1/L2/L3, action, status, attempts, last_error, done_by, done_at)—— 每 App 一行。
- `mxid_provisioning_link`(user_id, app_id, external_id)—— L2 幂等映射。
- `mxid_webhook_endpoint`(tenant_id, url, secret `crypto.Secret`, events, enabled)。
- `mxid_webhook_delivery`(endpoint_id, event, payload, status, attempts, next_attempt)—— 投递重试。

### 风险 / 诚实评估
- ✅ 不做"开户",L1 主体复用现有能力,纯编排,风险低。
- L1(CE 编排 + outbox)约 **2-3 周**,价值最大风险最低,**先做**。
- L3 待办 + webhook 约 **1.5-2 周**(webhook 子系统稍重:签名/重试/回调)。
- L2 SCIM 连接器(EE)约 **1-1.5 周**(默认关,可后置但本期全做)。
- outbox 触及禁用写路径:与事务边界对齐,先 commit 留历史。
- HA 必须真压测(杀副本验证任务不丢不重)。

### 工作量
全做 = L1+outbox(2-3w)+ L3 待办+webhook(1.5-2w)+ L2 SCIM(1-1.5w)≈ **5-6 周**。
顺序:L1 → L3 → L2(L1 拿核心价值,L2 默认关可最后上)。

---

## 三轴评估总览

| 维度 | P1.1 模板市场 | P1.2 离职销户/访问回收 |
|------|--------------|----------------------|
| CIAM/EIAM 最佳实践 | ✅ OIN 式声明模板 | ✅ Okta 式分层:能自动的自动,够不着的列报告 |
| 项目要求(CLAUDE.md) | ✅ 复用校验/authz/审计 | ✅ safehttp/KEK/step-up/EE 隔离 逐条满足 |
| 企业最佳实践 | ✅ 版本化、无密钥 | ✅ L1 掌控切断 + outbox 不丢 + L3 不假装 |
| CE/EE | CE | L1/L3/outbox/webhook 在 CE,L2 SCIM 连接器 EE(`scim`) |
| 风险 | 低 | 低-中(主体复用现有能力,纯编排) |
| 工期 | 1.5-2 周 | 5-6 周(L1+outbox+L3 双轨+L2 SCIM,全做) |

## 关键结论
1. **"自动开户"废弃**:下游 IT 自管、只给读权限,硬做不现实。本期只做**离职销户/访问回收**。
2. **按控制力分三层,全做**:L1 SSO 切断(CE,主体)/ L2 下游停用(EE,**SCIM 默认关**)/ L3 报告(CE,**Console 待办 + Webhook 双轨**)。
3. **L1 是 80%**:复用现有 session/token/back-channel logout,编排成一键离职,价值最大风险最低。
4. **outbox 是地基**:离职动作绝不能丢,事务性 outbox 保证补偿到成。
5. **工期**:全 Phase 1 现实 **7-8 周**(模板 1.5-2 + 离职全做 5-6)。
6. **顺序**:P1.1 模板 → P1.2 L1 → L3 → L2(L1 拿核心价值,L2 默认关最后上)。

## 已定决策(2026-06)
- ✅ **L1/L2/L3 全做**。
- ✅ **L2 SCIM per-app 开关,默认 OFF** —— 配好也不自动触下游,管理员显式开启才生效。
- ✅ **L3 = Console 待办 + Webhook 双做** —— webhook 给机器对接(可回调勾销待办),待办给人盯梢。
- ✅ App footprint 来源:org/group 授权 ∪ 实际登录过(复用 `AppLaunched`)。

## 已定决策(续,2026-06)
- ✅ **内置模板首批清单**(协议以各 App 实际支持为准,接入文档核对):
  飞书 / 钉钉 / 企业微信 / GitLab / Grafana / Jira / **Confluence** / **JumpServer** / Jenkins。
  - JumpServer 社区版仅 **CAS**(见协议支持矩阵);Confluence/Jira 用 **SAML**(Atlassian DC);
    Grafana/Jenkins 用 **OIDC**;GitLab 社区版 SAML 受限,默认 OIDC。
- ✅ **空协议 `jwt`/`form` 已清理**(本会话已执行):
  无后端 handler、看着支持实则没有 → 全部移除,**避免用户误以为支持**。
  - 后端:`app/model.go` 删 `ProtocolJWT`/`ProtocolFORM` 常量;`app/dto.go` `oneof` 收窄为 `oidc saml cas`。
  - 前端:`apps/index.tsx` 删颜色/字段/下拉项/JWT 详情块;`shared` 删 `AppProtocol.JWT/FORM`、`protocolLabel`、i18n jwt 文案。
  - 删空目录 `internal/protocol/{jwt,form}`。
  - 验证:`go build ./...` ✅ + console `tsc --noEmit` ✅。**未提交**(待用户指示)。
  - 如未来要做 M2M,走 OIDC `client_credentials`(已实现),不复活独立 jwt 协议。

## 实现状态(2026-06,已落地)
P1.1 + P1.2 均已实现:
- **P1.1 模板市场(CE)** ✅ —— `internal/domain/app/templates/*.json`(go:embed)+ 控制台模板选择器 + 品牌图标。
- **P1.2 L1 一键离职(CE)** ✅ —— `internal/domain/offboarding`:禁用 + 撤会话(三命名空间)+ OIDC 刷新拒发(禁用用户)+ back-channel 扇出 + `user.offboarded` 审计 + 控制台「一键离职」按钮。
- **P1.2 L3 复核清单 + Webhook(CE)** ✅ —— `mxid_offboarding_task/item` + 控制台「离职复核」面板 + 签名 webhook(系统设置可配),投递走 outbox。
- **P1.2 outbox 地基(CE)** ✅ —— `internal/outbox`(`mxid_outbox`,`SKIP LOCKED` worker + 退避 + 死信)。
- **P1.2 L2 SCIM 停用(EE)** ✅ —— per-app 供应配置(`mxid_app_provisioning`,CE,默认关)+ `mxid-ee/features/scim` 连接器(SCIM 2.0 `PATCH active=false`,`license` 门控 `scim`,经 registry seam `OutboxRegister`/`ProvisioningConfig` 接入)。
  - **覆盖面注意**:通用 SCIM2 连接器主要吃**国际 SaaS(多为企业档)**;**国产飞书/钉钉/企微不走标准 SCIM**,需后续各写**私有 deprovision 适配器**(复用同一 outbox + Connector 接口)。
- **CE/EE 协同开发**:两仓置于容器目录 `mxid/{mxid,mxid-ee}`,EE 经 `replace => ../mxid` 实时联动(未用 go.work —— 本机 go 1.25.5 与 pin 的 1.25.11 冲突)。
