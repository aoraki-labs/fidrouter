# fidrouter — 产品与设计方案

> 本文档综合了迭代讨论后的最终设计,取代早期零散描述。一句话:**不让用户"相信"中转不记录,而让他们"验证"。**

---

## 0. 核心切分:两个独立产品

| | 产品 ①(核心)| 产品 ②(可选/自营)|
|---|---|---|
| 名字 | **fidrouter 中立可验证无日志平台** | **我们自己的 New API(自营中转)** |
| 是什么 | enclave 数据面 + verify SDK + 中立验证页/注册表 | 一套 New API 控制面,我们下场当中转 |
| 中立性 | **中立**,不绑任何一家控制面 | 非中立(我们是运营方之一)|
| 作用 | 卖"可验证无日志 + 合规" | **产品①的第一个客户(dogfood)** + 自营收入 |
| 关系 | 控制面无关,兼容任意中转栈 | 挂在产品①底下,和别的合作方平级 |

**关键:产品①不需要我们自己的 New API。** 我们自己的 New API 只是"第一个内部客户",用来验证和打样;它和别人的 New API 一样,只是产品①的一个控制面接入方。

---

## 1. 各方与信任边界

```
终端用户 ── 中转站(合作方,有 New API+用户+号池) ── 我们(中立可信平台) ── 上游官方(Anthropic/OpenAI)
  验证方          控制面:发令牌/计费/看板              被度量的无日志数据面        真正推理(边界之外)
```

- **能证明**:我们这一跳跑的是公开、可复现、无日志的代码,在真 TEE 里,且只连真厂商端点。
- **不能证明**:上游官方自己记不记录(那是它的 ZDR 条款);我们只锁死"第一跳"。

---

## 2. 可信平台设计(产品①)

### 2.1 组件
- **`cmd/fid-proxy` — enclave 数据面**:唯一看明文 prompt 的进程(仅内存),不落任何请求/响应体。跑在 GCP Confidential Space(Intel TDX)。OpenAI 兼容 `/v1/chat/completions` + 密封 `/v1/infer`。
- **verify SDK(`sdk/`)**:`from fid import OpenAI` drop-in,发送前验度量值(fail-closed)+ attested E2EE + 验签名回执(防降级)。
- **中立验证页 + 注册表(`verify-page/`)**:独立主机,现场验端点 + 验单次回执;`registry.json` = 度量值→开源构建+enclave 公钥。**必须独立于任何运营方**(被验证方控制验证器 = 没验证)。

### 2.2 密钥与身份(镜像里没有任何私钥)
| 材料 | 公/私 | 在哪 |
|---|---|---|
| CP 公钥(验能力令牌)| 公 | 烤进镜像 `config/public.json` |
| 期望度量值 | 公 | `public.json` + 注册表 |
| enclave 身份私钥(签 quote/回执)| 私 | **启动注入**(`FID_IDENTITY_SEED`),非镜像;下一步进 KMS |
| CP 签名私钥(签能力令牌)| 私 | **只在控制面**,永不进数据面镜像 |
| 上游 provider key | 私 | **BYOK 封进 enclave**(见 2.5)|

→ 开源镜像**无秘密**,度量值与 key 值无关。

### 2.3 授权:能力令牌(离线验签,enclave 不回调中转站)
- 能力令牌 = 签名 JSON `{tenant/用户id, pool, models[], quota, exp, isolated} + Ed25519(CP私钥)`。
- 合作方(cp-adapter 或 New API 内嵌)用 **CP 私钥签**;enclave 用 **CP 公钥离线验签 + 验 claims**,**不访问中转站**。权威嵌在签名里。
- 客户端"取令牌"(碰合作方一次)与"调用"(只碰 enclave)分离。

### 2.4 隐私:attested E2EE(封给度量值,不是封给域名)
- 客户端发送前把 prompt 用 **被证明的 enclave 公钥** X25519+AES-GCM 封装 → 中间任何一跳(包括合作方)只见密文。
- **信任来自 attestation,不来自 URL** → 所以 CNAME(合作方品牌域名)也安全。

### 2.5 BYOK 与 operator-blind(已定 = B,sealed BYOK)✅
- **已实现 B(最强)**:enclave 每次启动在 RAM 里生成一对 X25519 封装密钥(私钥永不落盘、运营方看不到),`/sealing` 用被度量的身份私钥**签名**发出公钥;客户验完 enclave 后把上游 key **封给这个度量值的 enclave**,密文经 `/byok` 提交,明文只在 RAM。控制面/镜像/环境变量里**没有任何明文 key**(实测 0 处)。
- 残留(可接受):重启后封装密钥变 → 需 `ctl seal-byok` 重封;这是 operator-blind 的必然代价(密钥不落盘)。
- 曾评估过的 **A**(KMS/Secret Manager + IAM 绑 `image_digest`):更省事但项目 owner 可改 IAM,故没选。
- 这块 = 前端"BYOK 录入"那半:`ctl seal-byok` 就是一个 web 表单的命令行版。

### 2.6 上游白名单 + 多上游认证适配器
- **测量代码里写死 `allowedUpstreamHosts={api.anthropic.com, api.openai.com}`** → "只连真厂商、不连中间人"由度量值可证。加厂商 = 评审过的代码改动。
- **上游认证做成可插拔适配器**:API key(现)、云凭证(Bedrock/Vertex,可加)、合法的 API-OAuth。
- **不做**:消费订阅 OAuth(Claude Code 登录态)转中转 —— 违反 ToS + 把 Agent SDK 塞进 enclave 会炸掉可审计性。订阅无法合法转 API key,让客户自去 console 开 API key。

### 2.7 计量与回执(签名元数据,旁路回传,永不回传内容)✅
- 每次请求 enclave 出**签名回执**:`{tenant/用户id, model, prompt+completion tokens, cache_hit, ts, measurement}`,**无 prompt/回复内容**,Ed25519 签。
- **已实现旁路 push**:`FIDPROXY_METERING_URL` 一设,enclave 每出一张回执就异步 POST 到该地址(`console/server.py` 的 `/ingest`)。也可组合 pull API / 客户端回传 / 批量对账。
- **回执可验签** → 合作方(及我们)能确认计量真来自被度量 enclave,**连我们都改不了这个数**。`/ingest` 收到后先按注册表用该度量值对应的 enclave 公钥**验签**,验不过(伪造/未知度量值)直接拒 → 用量不可伪造。既计费又对账(防抵赖)。

### 2.8 可复现构建(内容级)+ 注册表
- fid-proxy binary **字节级可复现**(`-trimpath -buildvcs=false -ldflags=-buildid= CGO_ENABLED=0`)。镜像 = 钉死的 distroless 基底 + 该 binary + 公开配置。
- `scripts/reproduce.sh`:重建 binary,`LIVE=<镜像>` 时抽活镜像内 `/app/fid-proxy` 比对 → 证明"活 enclave 跑的就是这份开源"。(镜像 manifest digest 因 buildkit 可推送 exporter 的时间戳非确定而不字节复现,故用内容等价校验。)
- 注册表 = 度量值→开源 commit + enclave 公钥;SDK/验证页据此判断该信什么。

### 2.9 接入 URL:CNAME(推荐)vs 直连
- **CNAME**(合作方二级域名 → enclave,TLS 在 enclave 内终结):合作方保品牌,配 verify SDK(E2EE)后无安全质疑(信任来自 attestation)。
- 直连(用我们域名):更简单更显中立,合作方丢品牌。
- ❌ 不能让合作方服务器代理转发(那就倒一手看明文,破无日志)。

---

## 3. New API 设计(控制面)

### 3.1 角色:控制面,**不在数据路径**
New API 干:发用户令牌、计费、看板、渠道(BYOK)、后台。**用户请求不经过它**(经过就看到明文破无日志)——它靠 enclave 旁路回传的**签名计量**得到用量。

### 3.2 合作方 New API 的 4 处集成
1. **签/换能力令牌**:内嵌 CP 私钥直接签发能力令牌,或旁挂 cp-adapter 把 `sk-` 换成能力令牌。
2. **BYOK 录入入口**:前端让运营方验 enclave → 把上游 key **封**进去(= operator-blind 的封装那半)。
3. **计量 ingest**:配一个回调地址,收 enclave 的签名回执 → 按用户聚合 → 计费/看板。
4. **用户身份透传**:令牌里带用户 id,使计量可归属到"他的哪个用户"。
> 轻量接法:不改 New API 核心,旁挂 cp-adapter + 计量 ingest webhook 即可;深度接法才 fork New API。

### 3.3 我们自己的 New API(产品②)= 第一个客户 + 结算
- 作为产品①的第一个 BYOK 客户跑通样板。
- **额外职责:我们侧计费** —— 我们也留一份 enclave 计量,按**每个合作方**聚合,给合作方开账(平台费/用量,或对其"可验证档"溢价分成)。

### 3.4 合作方控制台(`console/`)= 计量 ingest 的参考实现 ✅
- **一个可直接跑的最小控制面**:`/ingest` 收 enclave 签名回执 → 验签 → 按用户聚合;`/api/usage` 出 JSON;首页两个 tab:**用量看板** + **产品文档**(直接渲染本 DESIGN.md,做到"文档就在产品里")。
- 合作方要接自己的 New API:把计量回调指到自己的 `/ingest` 等价端点即可,**不必用我们这套**;这份是样板 + 我们自己产品②的控制台。
- 本地验证:`scripts/test-metering.sh`(mock enclave → 签名回执 → console,含"伪造回执被拒"用例)。

---

## 4. 一次请求全流程(四方)

```
事先:合作方 ① BYOK 封上游 key 进 enclave  ② 给用户发令牌  ③ 配计量回调
每次:
 用户/SDK ─验度量值(对中立注册表,fail-closed)→ E2EE 封 prompt + 带能力令牌 ─▶ enclave
 enclave ─离线验令牌→ RAM 解密 → 解封上游 key → TLS 直连上游官方 → 答案
 enclave ─E2EE 封回用户 + 签名回执─▶ (用户验回执/防降级) & (旁路回执→合作方+我们各一份计量)
```

---

## 5. 商业模式与收费

- **开源边界**:数据面 fid-proxy + verify SDK + 构建流水线**必须开源可复现**(否则可验证性归零,Apache-2.0);控制面/计费/路由策略**不必开源**。
- **四条线**:① 可验证中转(BYOK,按量,卖可验证溢价非搬运差价)② 企业订阅(专属 enclave/数据驻留/等保信创审计,最高毛利)③ **验证层/公证(给别家中转背书,认证/分成/注册表,最像护城河)** ④ 注册表+监测 SaaS。
- **护城河 ≠ 代码**(开源谁都能跑)= 被广泛信任的**中立注册表/SDK** + 合规资质 + 先发 + 网络效应(像 CA 根)。
- **成本低**:enclave 只是转发代理不做推理(推理由 BYOK key 付),边际成本≈CPU+流量;量大横向加 enclave。
- **两层计费,同一份签名计量**:合作方↔终端用户(合作方 New API 收);我们↔合作方(我们侧计量 → 开账)。
- **定价锚点**:对标审计/合规工具(等保/SOC2/GDPR),不对标 token 差价。

### 5.1 开源策略(关键:开源不是风险,是可验证性的前提)
问题:全开源竞争者一下就复制部署?要不要先闭后开?还是只开 fid-proxy?还是 1v1 NDA 共享?

结论 —— **按层拆,而不是按时间拆**:

| 层 | 开/闭 | 为什么 |
|---|---|---|
| 数据面 `fid-proxy` + verify SDK + 构建流水线 | **必须公开** | 用户"验证而非信任"的东西**就是这份代码**。看不见的代码 = 无法验证 = 产品价值归零。藏起来等于把"可验证中转"降级成又一个"相信我不记日志"。 |
| 控制面 / 计费 / 路由与缓存策略 / 注册表后端 / 企业集成 | **闭源** | 这些不影响可验证性,却是运营与差异化所在。 |

- **"竞争者复制 fid-proxy" 不是威胁,反而对我们有利**:数据面本来就是**简单转发代理**(几百行),真正的护城河不在代码,而在**被广泛信任的中立注册表/SDK + 合规资质 + 先发 + 网络效应**(像 CA 根证书:OpenSSL 开源,但你信的是 CA 这个机构与它的根)。别人多跑几个可验证 enclave → 都来我们注册表登记 → 我们越像"标准",网络效应越强。
- **"先闭后开" 不建议**:早期恰恰最需要用可验证性建立信任;闭源期你和普通中转站没区别,拿不到"可信"这个卖点,还错过最该讲故事的窗口。
- **"1v1 NDA 共享部署" —— 分清用在哪层**:
  - ❌ 用在**数据面**是自相矛盾:NDA 代码不能公开审计 → 客户仍只能"信你",可验证性塌回零。
  - ✅ 用在**企业版/控制面**完全合理:私有化部署、定制集成、专属 enclave、数据驻留,走商务合同 + NDA + 部署共享,这正是产品②/企业线的收费方式(最高毛利)。
- 一句话:**数据面越公开越值钱,控制面靠闭源和资质赚钱。** 当前 `github.com/aoraki-labs/fidrouter` 已公开的正是数据面 + SDK + 构建,方向正确;如果你更想走"早期只对签约客户开放"的路线,我们可以把仓库转私有、以 NDA 单独授予——但那会牺牲上面的可验证卖点,需要你权衡。

---

## 6. 现状(2026-08-04)与路线图

**Live**:enclave `34.158.56.83:9090`(fidrouter,distroless,`sha256:332d19c5…`,**operator-blind sealed BYOK** —— 重启后需 `ctl seal-byok` 重封)· 验证页 `https://verify.136-85-124-88.sslip.io`(现场绿灯)· 开源 `github.com/aoraki-labs/fidrouter`。已通:真 TEE + 度量值覆盖代码 + attested E2EE + 能力令牌 + 签名回执 + operator-blind sealed BYOK 真 Claude + OpenAI 兼容端点 + drop-in SDK + 内容级可复现 + 中立验证页/回执验证 + **计量 webhook 外发 + 合作方控制台(验签计量/用量看板/内嵌文档)**。

**路线图**
- **P1(收尾)**:合作方前端注册入口 + BYOK 录入做成 web 表单(命令行版 `ctl seal-byok` 已可用)· 计量控制台上线到 verify 同主机 · enclave 重部署带 `FIDPROXY_METERING_URL`/`FIDPROXY_VERIFY_URL`。
- **P2**:DCAP/ITA 链验证去 stub · 透明日志(代码度量值随时间)· 上游认证适配器(云凭证)· CNAME + 证书委托。
- **P3**:企业版落地页 + 开通流程 · 多区域/数据驻留 · 结构性无日志加固 · 公开审计。
- **P0 安全**:轮换 `.env` 里的明文凭据(root SSH / admin / 已泄露的 Anthropic demo key)。
