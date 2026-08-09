# How to verify that a fidrouter relay really is "no-log" (trust model)

> Answering: "The client side is plaintext, so how do you make an end user of some relay believe it really uses fidrouter and really keeps no records?"

## Core principle
**Trust cannot come from a relay claiming it uses fidrouter. Trust must be carried out by the user's side, or be checkable by a third party unrelated to the relay.**
The party being verified controlling the verifier = no verification (same as TLS: a certificate only means something when the browser validates it, not when the server says "I have a certificate").

## Trust ladder (from invalid to strongest)

### Level 0 ❌ Invalid
The relay's website says "we use fidrouter / no-log." Pure assertion, worth nothing.

### Level 1 ✅ Primary mechanism: the user's side runs the open-source verify SDK
**Before sending any prompt**, the SDK (on the user's device) automatically:
1. `GET /attestation?nonce=<random>` to fetch the quote;
2. verifies `measurement == the published reproducible-build value in the public registry`;
3. verifies the quote's signature chains to the hardware root (Intel TDX DCAP → Intel PCS);
4. verifies `report_data == H(nonce ‖ ephemeral_pub)` (replay protection + binding of the channel key);
5. if any step fails → **fail-closed, never send**.
Only after passing does it **seal the prompt in place** to the "attested key." → Trust comes from **code on the user's own machine**, independent of the relay's claims.
> "The client side is plaintext" is fine: the plaintext exists only inside the user's device and only before sealing; as long as the SDK is trustworthy (open source, self-buildable), plaintext never leaves the device before verification.

### Level 2 ✅ Provable after the fact: signed receipt + public transparency log
Every response carries an **enclave-signed receipt** (containing `measurement / model / req&resp hash / tokens`, **without the content**), appended to a **public append-only transparency log**.
- The user's App or any auditor can later verify: "this response really came from an attested no-log enclave," and that `model == request` (anti-downgrade).
- Inclusion can be checked, preventing the relay from dropping or tampering with receipts.
- A non-technical user's App can display "✓ Verified" based on this.

### Level 3 ✅ Neutral third party: a verification page / registry on our domain
An **independent monitor** continuously performs remote attestation against registered relay endpoints and publicly shows "current measurement == published." **Users check our site, not the relay's self-description.** Analogous to the neutral notarization role of a CA / Sigstore.

### Fallback: when the user doesn't control the client (consumer Apps)
- The App integrator **enables SDK verification by default** and passes the "✓ Verified" badge through to the end user;
- or provides a **browser extension / standalone verifier** to be installed on the user's side, bypassing the App's self-attestation.

## Hidden risks and countermeasures
- **Risk**: the relay ships a **modified "client"** of its own that steals the plaintext before sealing → nullifying Level 1.
- **Countermeasure**: the SDK is **open source + run/audited on the user's side**; combined with Level 2/3 (receipt + independent registry) for a second, **relay-independent** cross-check.

## Honest boundary
Same as TLS: **it only protects users who actually verify**. The product therefore has to make verification the **default path** (SDK verifies automatically, App shows the badge by default) and provide an independent checking channel. And all guarantees cover **only this one relay hop**; the upstream provider's behavior is out of scope.

## Do all relay users "encrypt locally before sending"?
- **When using the verify SDK: yes.** The SDK first performs attestation on the user's device, then uses HPKE to **seal the prompt in place to the attested key**; only ciphertext reaches the relay, and only the attested enclave can decrypt it.
- **When only changing `base_url`, without verifying or sealing: not a strong guarantee.** That is ordinary TLS to the enclave (encrypted on the wire, terminated by the enclave), but it lacks the strong binding of "only attested code can decrypt" and lacks client-side evidence.
- **Product goal**: make attested-E2EE the **default path**. The only cost is a single **reusable** attestation handshake, still drop-in (change base_url + `verify=on`).

## Corresponding implementation in this repo (PoC)
`cmd/client` already implements Level 1 (attest → verify measurement/signature/nonce → fail-closed → seal → verify receipt including model for anti-downgrade). The Level 2 receipt is already produced and validated by the client; the transparency log and Level 3 registry are in plan B8 (P3).
