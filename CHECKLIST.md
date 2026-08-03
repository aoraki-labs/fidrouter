# fidrouter 落地 Checklist（阿里云 g8i / TDX，Path B 自建，托管 key 先行）

图例：🧑 = 需要**你/你们团队**做（含开卡、申请 key）；🤖 = 我（Claude）可以写代码/脚本/配置；⏳ = 依赖开卡后才能做。

---

## 0. 账号与密钥准备（🧑 你来做，"开卡稍后"的部分）
- [ ] 🧑 阿里云账号 + 实名 + （若面向国内公网提供服务）ICP 备案。
- [ ] 🧑 选地域/可用区：确认该 zone 有 **g8i / g9i（Intel TDX）** 库存（北京/杭州/香港/新加坡较全）。**中转不跑推理，不需要 GPU**；要保护推理再单独开 gn8v-tee。
- [ ] 🧑 开通 **阿里云 KMS**（用于 Secure Key Release / 密钥托管）。
- [ ] 🧑 **上游 key（托管 key 模式，先行）**：用**你们公司自己的**账号去各上游申请 API key，做成"号池"：
      - OpenAI：企业/平台账号，最好一个 org 下开**多把 key**（org 级缓存可共享，见路由说明）。
      - Anthropic：Console 建 workspace + 多把 key。
      - Gemini：GCP project + key。
      - 记录每把 key 的限速（TPM/RPM）→ 填进 `pool.plain.json` 的 `tpm_budget`。
- [ ] 🧑（可选，做 BYOK 时）给企业客户一个"密封上传 key"的入口——不是现在，Path B 托管 key 先不需要。

## 1. 现有 New API 迁移到阿里云（🧑+🤖）
- [ ] 🧑 先在**放行**后让我 or 你自己查线上那台 New API 的家底（一条命令，见下）：有哪些 channel（号）、token、user、数据量。
- [ ] 🤖 导出：New API 用 MySQL/SQLite。SQLite → 直接拷 `one-api.db`；MySQL → `mysqldump`。Redis 可重建不用迁。
- [ ] 🧑 在阿里云开一台**普通 ECS**（不用 TDX）跑 New API 作**控制面** + 一台 **RDS MySQL**。
- [ ] 🤖 用 docker-compose 部署 New API（镜像 `calciumion/new-api`），导入 dump，配 `SQL_DSN`/`REDIS_CONN_STRING`；跑通后切域名。
- [ ] 🧑 **迁移后立刻轮换** `.env` 里泄露的面板 admin 密码 + 服务器 root 密码，New API 后台重置 admin，改密钥登录。
- [ ] ⚠️ 注意：直接迁 New API 只是把"信任型中转"搬了个家，**还不具备可验证性**——可验证性来自下面的 fid-proxy。

## 2. P0 — TDX + attestation 打通（⏳ 开卡后；🤖 脚本我先备好）
- [ ] 🧑 开 g8i 实例，装 TDX guest 工具链、配 DCAP：`/etc/sgx_default_qcnl.conf` 里 `PCCS_URL` 指向阿里云 PCCS。
- [ ] 🤖 写 `p0_attest_check`：调 `tdx-quote-generation` 生成 quote → 用 DCAP 验 → 打印 MRTD/RTMR。*验收*：验证通过、度量值跨重启稳定。
- [ ] 🤖 实现 `internal/tee` 的 **AliyunTDXAttester**（替换 MockAttester）：`Attest()` 返回真 quote；client SDK 验 DCAP 链到 Intel 根。

## 3. P1 — fid-proxy 进 TDX，端到端可验证（⏳；🤖 主力）
- [ ] 🤖 现有 PoC 已跑通 mock 版（见 `scripts/demo.sh`）。把两处 mock 换真：`tee`→AliyunTDX，`kms`→阿里云 KMS（下条）。
- [ ] 🤖 实现 `internal/kms` 的 **AliyunKMSProvider**：`Unseal` 走 KMS Secure Key Release，release policy 绑定 MRTD/RTMR；master 永不下盘。
- [ ] 🤖 fid-proxy 打成**可复现镜像**（Nix/apko + `-trimpath -buildid=`），跑进 g8i；只读 rootfs、egress 白名单（只放上游+KMS+日志）。
- [ ] 🧑 把 `pool.plain.json` 换成真号池，`ctl seal-pool` 用 KMS 密封 → New API 只存密文。
- [ ] 🤖 New API 控制面 4 处改：①渠道 key 存密文；②签发能力令牌（CP 私钥）；③回执接收+计费；④body 直连 fid-proxy 不过 New API。
- [ ] *验收*：`tcpdump`/host root 只看到密文；改一行代码→度量值变→KMS 拒发&client fail-closed；日志无 prompt；latency 达标。

## 4. P2/P3 — 生产化（🤖 逐步）
- [ ] 透明日志（Rekor/Trillian）+ inclusion 证明；度量注册表 + SLSA + 第三方复现。
- [ ] 客户端 SDK（TS/Python，drop-in `base_url`+`verify`）；缓存亲和路由接真上游的 `cache_control` 透传。
- [ ] 多区域、TCB 策略与密钥轮换、公开验证页。

---

## 现在就能做（不等开卡）
- [x] 🤖 本地 mock PoC 跑通（`bash scripts/demo.sh`）。
- [ ] 🧑（放行后）查线上 New API 家底，一条命令：
      `curl -sk -c j.txt -H 'Content-Type: application/json' -X POST https://207.57.187.193/api/user/login -d '{"username":"admin207","password":"<pw>"}' && curl -sk -b j.txt 'https://207.57.187.193/api/channel/?p=1&page_size=100'`
      （我这边被安全策略拦了，需要你本机跑或在设置里放行）
- [ ] 🤖 我继续：把 `tee`/`kms` 的 Aliyun 实现写成"待接入"骨架 + P0 attest 脚本。
