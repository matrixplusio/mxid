# MXID 工业级 EIAM 补齐路线图

> 目标:从"协议网关"跨到"工业级 EIAM",对标 Keycloak / Auth0 / Okta / TopIAM。
> 基线评估见对话纪要;本路线图按 ROI(价值/成本)排期。
>
> **范围说明**:LDAP/AD 入站联邦本轮**不做**(存量身份对接需求暂不优先)。
> 一旦目标客户出现 AD 存量场景,需重排到 P0。

## 当前定位

协议核扎实(OIDC 全套 / SAML2 / CAS v1-3),安全基线(SSRF / KEK / 审计 / step-up)
达标甚至超部分开源。缺的是企业"连接层 + 治理层"。

## 缺口清单(去除 LDAP 后)

| # | 缺口 | 工业级标杆 | 影响 | ROI |
|---|------|-----------|------|-----|
| G1 | 应用接入模板市场 ✅ 已实现 | Okta/MaxKey 数百模板 | 接入成本高,运维劝退 | 高 |
| G2 | 出站供应 / SCIM push ✅ 已实现(离职销户 L1/L3 CE + L2 SCIM EE) | Okta provisioning | 离职账号清理靠人工 | 高 |
| G3 | 身份编排 / 认证流引擎 | Keycloak Auth Flows | 认证逻辑写死,无风险驱动 | 高 |
| G4 | 合规治理(access review/报表) | Okta/SailPoint | 过不了大客户合规 | 高 |
| G5 | 分级管理 + 审批工作流 | 所有工业平台 | 无委派管理,无自助申请 | 中 |
| G6 | 集群 / HA 验证 | Keycloak Infinispan | 单点,无滚动升级 | 中 |
| G7 | 协议边角(device flow/CIBA/DPoP) | Keycloak | IoT/CLI 登录缺失 | 中 |
| G8 | 集成生态(webhook/Terraform/SDK) | Auth0/Okta | 无 IaC 接入 | 中 |

---

## 排期

### Phase 1 — 接入与生命周期(P0,~6-8 周)

让客户"进得来、接得上、清得掉"。直接决定能否落地交付。

#### P1.1 应用接入模板市场(G1)
- **做什么**:把现有手填的 app 创建,改为模板驱动。模板 = 预填 protocol +
  默认 redirect/claim mapping + 接入文档片段 + 图标。内置常用 SaaS
  (飞书 / 钉钉 / 企业微信 / 腾讯会议 / Jira / GitLab / Grafana / Jenkins …)。
- **架构**:模板存 JSON(`internal/domain/app/templates/*.json`),
  console 创建向导渲染模板表单。模板可热更新(后续做模板包下载)。
- **EE 边界**:模板市场全在 CE(降低接入门槛是核心卖点);
  企业私有模板上传 / 同步走 EE。
- **验收**:从模板创建 OIDC/SAML 应用 < 5 字段;接入文档自动生成。

#### P1.2 出站供应 / SCIM push(G2)
- **做什么**:把 MXID 身份推到下游 SaaS(自动开户 / 改属性 / 销户)。
  对接 SCIM 2.0 出站 + 主流 SaaS 私有 API 适配器。
- **架构**:`internal/domain/provisioning/`,事件驱动(用户 CRUD / 组变更 →
  推送队列 → 下游连接器)。连接器接口化(SCIM 通用 + 私有适配)。
- **安全**:出站全走 `pkg/safehttp`;下游凭证走 KEK 加密存储。
- **EE 边界**:出站供应是高价值企业功能 → **EE 代码隔离**
  (`mxid-ee`,feature key `provisioning` 或复用 `scim`)。
- **依赖**:先做 P1.1(应用模型)。
- **验收**:用户禁用 → 下游 SaaS 账号自动 deactivate,审计留痕。

---

### Phase 2 — 治理与编排(P1,~8-10 周)

让平台"管得住、审得了"。决定能否进大客户 / 过合规。

#### P2.1 身份编排 / 认证流引擎(G3)
- **做什么**:认证步骤可配置化。条件分支(IP / 设备 / 风险 / 用户属性)→
  动态决定是否 MFA、走哪种 factor、是否阻断。对标 Keycloak Auth Flows /
  Auth0 Actions。
- **架构**:认证流 DSL(有向步骤图),`internal/domain/authflow/`。
  执行器在 `authn` 登录管线插入 hook 点。现有 step-up / 条件访问收编为流中节点。
- **EE 边界**:基础流(密码 + MFA)在 CE;高级条件节点(风险 / 设备 / 自定义脚本)
  EE 门控(复用 `conditional_access` / `advanced_stepup`)。
- **风险**:改动 `authn` 登录核心管线,需充分测试 + 灰度。
- **验收**:可视化配置"境外 IP 强制 MFA + 限制应用范围",无需改代码。

#### P2.2 合规治理 — Access Review + 报表(G4)
- **做什么**:
  - **Access Review / Recertification**:周期性生成权限审阅任务,
    管理员确认 / 撤销用户的角色 / 应用访问,留痕。
  - **报表**:登录分析、权限分布、异常登录、合规导出(等保 / SOC2 字段)。
- **架构**:`internal/domain/governance/`。审阅任务 = 快照 + 审批状态机。
  报表基于现有审计 + 权限数据聚合(只读视图)。
- **EE 边界**:Access Review + 高级报表 → EE(合规是大客户付费点)。
  基础审计列表 / 导出留 CE。
- **依赖**:复用现有 audit + Casbin 数据。
- **验收**:生成季度权限审阅,导出合规报告 PDF/CSV。

#### P2.3 分级管理 + 审批工作流(G5)
- **做什么**:
  - **委派管理**:租户管理员只管自己租户;按 org/group 划分管理范围。
  - **自助申请 + 审批**:用户申请角色 / 应用访问 → 审批人确认 → 自动授权。
- **架构**:扩展 Casbin scope(已有 `authz.Require(perm, scope)` 基础)。
  审批 = 工作流状态机,`internal/domain/approval/`。
- **EE 边界**:多级委派 + 审批流 → EE。
- **依赖**:P2.2 治理域可共用审批状态机。
- **验收**:租户管理员无法越权操作其他租户;申请-审批闭环可用。

---

### Phase 3 — 韧性与生态(P2,~6-8 周)

让平台"扛得住、连得广"。规模化交付的基础设施。

#### P3.1 集群 / HA 验证 + 加固(G6)
- **做什么**:验证多副本无状态运行。会话(Redis)/ 票据 / 限流已 Redis 化,
  需确认:protocol 会话一致性、签名密钥多副本共享、滚动升级零中断。
- **架构**:无新域;补 Redis 集群 / 哨兵支持、PG 主从读写分离配置、
  健康检查 + 优雅退出。
- **验收**:3 副本滚动升级,登录态不丢;杀一个副本无感。
- **注意**:CLAUDE.md 承认"CI 是唯一验证者" → HA 必须真实压测,不能只过 CI。

#### P3.2 协议边角补全(G7)
- **做什么**:
  - **Device Authorization Flow**(RFC 8628)— IoT / CLI / 智能电视登录。
  - **CIBA**(可选,银行 / 高安全场景)。
  - **DPoP**(RFC 9449)— 令牌绑定,防重放。
  - 清理空目录 `internal/protocol/{jwt,form}`(要么实现 JWT/M2M 颁发,要么删)。
- **架构**:扩展 `internal/protocol/oidc/`,新增 device endpoint + 轮询。
- **验收**:`device_code` grant 跑通;CLI 工具可登录。

#### P3.3 集成生态(G8)
- **做什么**:
  - **Webhook / 事件外发**:用户 / 应用 / 登录事件推外部 URL(走 safehttp)。
  - **Terraform Provider**:IaC 管理应用 / 角色 / 用户。
  - **管理 SDK**(Go / TS)封装现有 OpenAPI。
- **架构**:webhook = `internal/domain/webhook/`(订阅 + 投递 + 重试 + 签名)。
  Terraform provider 独立仓库,调现有 `/openapi/v1/*` + PAT。
- **EE 边界**:webhook 基础版 CE;Terraform / SDK 全开放(促生态)。
- **验收**:用户创建触发 webhook,签名可验;terraform apply 创建应用。

---

## 排期总览

```
Phase 1 (P0)  接入与生命周期    ~6-8 周   G1 模板市场 · G2 出站供应
Phase 2 (P1)  治理与编排        ~8-10 周  G3 编排引擎 · G4 合规治理 · G5 分级审批
Phase 3 (P2)  韧性与生态        ~6-8 周   G6 HA · G7 协议边角 · G8 生态
```

总计约 20-26 周(单人估算,可并行压缩)。

## CE / EE 切分原则

- **降低接入门槛的 → CE**:应用模板市场、基础 webhook、协议补全、Terraform/SDK。
  (接入越容易,装机量越大,EE 转化池越大。)
- **企业治理 / 高价值的 → EE 代码隔离**:出站供应、Access Review、高级报表、
  多级委派审批、编排引擎高级节点。
- 所有新 EE 功能走 `pkg/ee/registry` 注册,`garble` 混淆,CE 二进制不含其代码。

## 关键依赖与风险

1. **P2.1 编排引擎改 authn 核心管线** — 最高风险,需灰度 + 回滚预案。
   建议先 commit 留历史(参考 `app/run.go` 教训)。
2. **P1.2 出站供应** 依赖 P1.1 应用模型,顺序不可逆。
3. **P3.1 HA** 必须真实压测,CI 过 ≠ 生产可用。
4. 每个 Phase 落地后更新 `docs/EDITIONS.md` 的 CE/EE 矩阵。

## 未纳入(明确不做 / 暂缓)

- **LDAP/AD 入站联邦** — 本轮剔除(用户决策)。目标客户出现 AD 存量场景时重排 P0。
- ABAC(属性级授权)— 现 Casbin RBAC 够用,无明确需求不做。
- 行级安全(RLS)多租户 — 现 GORM tenant 插件够单区域,跨区再议。
