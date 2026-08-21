# web/ — browser code you are asked to trust

`byok.js` seals a partner's upstream provider key **in their browser** to the attested
enclave, so the platform only ever receives ciphertext. That makes it trust-sensitive: a
tampered copy served by the platform could capture the plaintext key before sealing.

It is published here so you can **diff what the platform serves against this source**:

```bash
curl -s https://app.fidcore.xyz/static/byok.js | sha256sum
# expected (this file):
# 1f50300d1d119a132c0cce5d519c5a4c38b2b468756bb3335814654f4353c963
```

If those differ, do not enter a key — open an issue. (The in-browser flow already verifies
that the enclave's per-boot sealing key is signed by the identity key pinned from the public
registry, so a substituted *sealing key* is rejected client-side; this hash check is what
covers a substituted *script*.)
