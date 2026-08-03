# Getting a real Intel TDX VM on this Aliyun account — findings & actions

## Confirmed diagnosis (account 5602185370292753, international)
Two independent hard blockers to launching a real TDX Trust Domain:

| Official TDX zone | Family | Can this account build real TDX? | Blocker |
|---|---|---|---|
| ap-southeast-1b (Singapore) | g8i | ❌ | g8i is **not on sale** there now (`Zone.NotOnSale`, empty stock). Overseas sells g9i, but g9i is **not TDX-enabled** overseas. |
| cn-beijing-i / -l (Beijing) | g8i/g9i/c9i (in stock) | ❌ | Account is **not real-name authenticated** (`RealNameAuthenticationError`) — mainland China requires real-name; even a plain non-TDX g8i DryRun fails. |

Note: ap-northeast-1 (Tokyo) g9i passed a DryRun but is NOT an official TDX zone — a real create silently produced a normal KVM VM (no `tdx_guest`). So Tokyo is not a path.

## Path A — Beijing (most reliable), requires real-name auth (NOT a ticket)
1. Complete **Real-name Authentication (实名认证)** on the account: Console → account avatar → **Real-name Registration** (individual: ID card; enterprise: business license).
2. After approval: `provision.py --region cn-beijing --zone cn-beijing-i --type ecs.g8i.xlarge --tdx --yes` builds a real TD (stock + official TDX support confirmed).
3. Trade-off: data resides in mainland China. ⚠️ An international-site account using mainland regions may need additional compliance (possibly a China entity).

## Path B — Singapore (overseas), requires Aliyun to make g8i/TDX available (ticket)
Submit at the **International ticket console**: `https://home-intl.console.aliyun.com` → **Support → Submit a Ticket** (`https://ticket-intl.console.aliyun.com`) → Product: **Elastic Compute Service (ECS)**.

**Subject:** Enable Intel TDX confidential VM (g8i) in ap-southeast-1b for my account

**Body:**
> Hello, I want to launch **Intel TDX Confidential VMs (机密计算)** in an OVERSEAS region and need help.
>
> **Account ID:** 5602185370292753 (international) · **RAM user:** hugo-al
>
> Per the docs, the only overseas TDX zone is **ap-southeast-1b (Singapore) with the g8i family**. However:
> - `DescribeAvailableResource` shows **g8i is not available/in-stock in ap-southeast-1** (empty result), and a `RunInstances` DryRun in ap-southeast-1b with g8i returns **`Zone.NotOnSale`**.
> - g9i **is** in stock in ap-southeast-1, but a TDX DryRun with g9i there returns `InvalidResourceType.NotSupported` (`grayBizType: gray_tdx`) — i.e. g9i is not TDX-enabled overseas.
>
> **Requests:**
> 1. Please enable/allowlist and provide stock/quota for **ecs.g8i (>= xlarge) in ap-southeast-1b** so I can create TDX confidential VMs there, **or**
> 2. Enable **Intel TDX for the g9i family in an overseas region** (e.g. ap-southeast-1, ap-northeast-1, ap-southeast-5), and tell me which region/zone + family my account can use for TDX.
>
> **Use case:** a confidential / verifiable no-log LLM inference relay PoC; the guest must boot as a TD (with `/dev/tdx_guest`) so it can produce a genuine TDX attestation quote verifiable via DCAP against the regional PCCS.
>
> Thank you.

## Recommendation
- If mainland China data residency is acceptable and you can real-name the account → **Path A** (fastest, reliable).
- If you require overseas → **Path B** ticket (outcome depends on Aliyun; g8i may be phasing out overseas).
- Meanwhile all our code is ready (provision `--tdx`, verify SDK, DCAP parser, ITA backend, KMS already enabled). We can also wire `AliyunTDXAttester` in dev/allow_unverified mode on a normal overseas VM to finish the plumbing while access is sorted.
