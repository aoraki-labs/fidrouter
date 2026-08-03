# fid-router — 实现现状 · 架构 · Demo · 落地清单

（截至 2026-07-31。配套设计见 docs/WHITEPAPER.md / VERIFICATION.md，可视化见 architecture 手册 artifact。）

## 1. 这个产品是什么
一个**可验证的无日志 LLM 中转**：用户在**发送 prompt 之前**，用硬件远程证明（Intel TDX）确认中转跑的是公开、不记录的代码，且 prompt 只在被证明的 enclave 内解密。把中转从"请相信我们"升级成"你可以验证我们"。**只覆盖中转这一跳**——上游厂商仍看到明文，受其自身条款约束。

## 2. 已实现的功能
- **远程证明 + fail-closed**：客户端发送前验证 TDX quote（度量值 + report_data 绑定），不通过就拒发。
- **attested E2EE**：prompt 用 HPKE 就地密封给 quote 里绑定的会话公钥，只有 enclave 能解。
- **签名回执**：enclave 对每次请求签回执（含 model，防偷偷降级），客户端验签。
- **缓存亲和路由**：按前缀指纹把同前缀固定到同一上游账号，miss→hit。
- **能力令牌**：控制面签 JWT（租户/模型白名单/配额），enclave 只验签不碰用户库。
- **密钥密封（mock）**：上游 key 密文存储，凭度量值门控释放（当前 MockKMS）。
- **双语言 verify SDK**（Python/TS，drop-in `chat()`）+ **DCAP quote 解析** + **Intel Trust Authority backend**（已实现自测）。
- **一键 provision**（阿里云 / GCP），GCP 已建出真 TDX VM。

## 3. 架构 · 真 vs Mock（当前状态）
| 组件 | 说明 | 现状 |
|---|---|---|
| TDX 机密 VM | GCP C3，真 Trust Domain（`/dev/tdx_guest`） | ✅ **真** |
| 真 quote 生成 | 内核 configfs-TSM，`TdxConfigfsAttester` | ✅ **真** |
| 度量值 pin + report_data 绑定 | 客户端验 MRTD + `H(nonce‖会话公钥‖回执公钥)` | ✅ **真** |
| attested E2EE + 签名回执 | X25519+AES-GCM + Ed25519 | ✅ **真** |
| 亲和路由 + 能力令牌 | 一致性哈希 + JWT | ✅ **真** |
| **DCAP 签名链验到 Intel 根** | ECDSA + PCK chain → Intel PCS | ⚠️ **stub**（`allow_unverified`；补齐=Intel QVL 或 ITA） |
| **度量值覆盖“我们的代码”** | 见 §5 关键项：MRTD 目前只度量 GCP 基础 VM，不含 fid-proxy | ⚠️ **关键缺口** |
| KMS 门控放 key | MockKMS（进程内） | ⚠️ mock（换 GCP Cloud KMS / Confidential Space） |
| 上游 | mock-upstream | ⚠️ mock（换真 OpenAI/Anthropic + BYOK） |
| 控制面（用户/计费） | ctl（mock New API） | ⚠️ mock（接 New API） |
| 透明日志 | 无 | ❌ 待做（Rekor/Trillian） |

## 4. Demo 流程（跑在真 GCP TDX 上）
盒子：`fid-proxy-tdx` / `35.247.164.62`（新加坡，计费中）。一条命令：
```bash
bash deploy/gcp/demo.sh
```
演示三幕：
1. **验证并发送**：客户端拉真 quote → 验度量值 + report_data 绑定 → 密封发送 → 验签名回执（`REAL-TDX verified`，cache miss）。
2. **同前缀再发**：亲和路由命中（`cache_hit=True`）。
3. **篡改**：客户端 pin 一个错误度量值 → **FAIL-CLOSED，什么都不发**。
（本地 Web UI 版：`node web/server.mjs` 后浏览器打开，填 endpoint/token/MRTD 点“验证并发送”。）

部署/重建全流程见 `deploy/gcp/README.md`。

## 5. 真正落地还要做什么（按优先级）

### P1 · 让"可验证"名副其实（最关键）
1. **度量值必须覆盖我们的代码**（当前最大缺口）。MRTD 现在度量的是 GCP 的 Ubuntu 基础 VM，**不含 fid-proxy 二进制**——所以现在证明的是"这是真 TDX VM"，还不是"这是我们那份审计过的无日志代码"。三条可选路径：
   - **GCP Confidential Space**：把 fid-proxy 打成容器，Confidential Space 把**容器镜像摘要**写进证明 token → 度量值 = 我们的镜像。**推荐**（GCP 原生、改动小）。
   - **dstack**（开源）：measure docker 镜像哈希进 report。
   - 自建 measured boot：把 fid-proxy 度量进 RTMR。
2. **DCAP 链验证**去 stub：在验证方装 **Intel QVL**（`libsgx-dcap-quote-verify`）或用 **ITA backend**，验 ECDSA + PCK 链到 Intel 根 + **TCB 状态**（拒过期）。去掉 `allow_unverified`。
3. **可复现构建 + 度量注册表**：fid-proxy 容器可复现构建（Nix/apko），发布 `源码→镜像摘要→度量值`，第三方可复现；客户端 pin 注册表值。

### P2 · 变成真中转
4. **真上游 + BYOK**：mock-upstream 换成真 OpenAI/Anthropic/Gemini 转发；忠实透传 `cache_control`；BYOK 密封上传客户 key。
5. **真 KMS**：MockKMS 换 **GCP Cloud KMS**（Confidential Space 门控释放）或 dstack-kms，上游 key 只对被证明镜像释放。
6. **控制面接 New API**：用户/计费/配额/后台用 New API；它签能力令牌、从回执计费；body 直连 enclave 不过 New API。
7. **签名回执 → 透明日志**（Rekor/Trillian）：可事后审计 + 客户端查 inclusion。

### P3 · 生产化
8. **结构性无日志加固**：只读 rootfs、无持久盘、egress 白名单（只放上游+KMS+日志）、fail-closed。
9. **服务化与可用性**：systemd（替 nohup）、TLS/RA-TLS 终止在 enclave（443）、多实例/自动扩缩、监控告警。
10. **SDK 打包**：pip/npm 发布，补全 OpenAI/Anthropic 请求映射，TS 与 Python 对齐 DCAP 链验证。
11. **公开验证页/注册表**：中立第三方持续证明已上线 endpoint，用户查我方站。

### P0 · 安全（立即）
- 轮换 `.env` 里仍在的明文 **root SSH 密码 + 面板 admin 凭据**；`.env` 移出版本库；密钥走 secrets manager；收紧防火墙（demo 期 9090 仅本机 IP，对外 demo 时按需放开）。

## 6. 一句话现状
**架构闭环已在真 TDX 上端到端跑通**（真 quote + 绑定 + E2EE + 回执 + 缓存）。离生产还差三件真东西：**①度量值覆盖我们的代码（Confidential Space/dstack）②DCAP 链验证（QVL/ITA）③真上游+真 KMS+控制面**。P1 做完就能对外讲"可验证无日志"而不含水分。
