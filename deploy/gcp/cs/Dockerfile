# Confidential Space workload image for fidrouter — REPRODUCIBLE by design.
# The image DIGEST is what Confidential Space attests (submods.container.image_digest),
# so anyone must be able to rebuild THIS source and get the SAME digest. To that end:
#   - base pinned by digest (no floating tag)
#   - distroless static: no apt (deterministic), no shell, minimal surface, ships CA certs
#   - the fid-proxy binary is built reproducibly (-trimpath -buildvcs=false -ldflags=-buildid=)
#   - built with buildx + SOURCE_DATE_EPOCH so layer timestamps are normalized
# NO private keys in the image: only public.json (cp_pub + expected measurement); the
# identity seed and upstream key are injected/sealed at boot.
FROM gcr.io/distroless/static-debian12@sha256:a9fcaedd4c9b59e12dd65d954f0b5044f19b0647a8a3712e77205df9e7b102cd
WORKDIR /app
COPY fid-proxy /app/fid-proxy
COPY config /app/config
# Metering + verify URLs are BAKED IN (not operator-injected) so the audited image
# proves exactly where signed metering (metadata only) is sent and which verify page
# it points humans to. They carry no secret and don't affect privacy (metering is
# signed metadata, no content), so measuring them only strengthens the audit story.
ENV FIDPROXY_ATTESTER=gcp-cs \
    FID_HOME=/app/config \
    FIDPROXY_POOL_PLAINTEXT=/app/config/pool.plain.json \
    FIDPROXY_ADDR=:9090 \
    FID_CS_AUDIENCE=fidrouter \
    FIDPROXY_METERING_URL=https://console.fidcore.xyz/ingest \
    FIDPROXY_VERIFY_URL=https://app.fidcore.xyz \
    FIDPROXY_TLS=1 \
    FIDPROXY_TLS_HOSTS=enclave.fidcore.xyz,34.158.56.83 \
    FIDPROXY_CP_ADAPTER_URL=https://cp.fidcore.xyz \
    FIDPROXY_HOSTED_EXCHANGE_URL=https://app.fidcore.xyz/api/cp \
    FIDPROXY_TLS_KEY_MODE=identity
# RA-TLS + the cp-adapter endpoint are BAKED IN on purpose (they carry no secret), so the
# measured image proves (a) TLS terminates in-enclave with its key bound into attestation and
# (b) exactly which cp-adapter a raw gateway key may be exchanged with — the latter matters
# because that is the one place a user's gateway key leaves the enclave. They are deliberately
# NOT in allow_env_override below: the hardened CS launcher refuses to start a workload when a
# non-allowlisted tee-env is supplied, and more importantly an operator must not be able to
# silently redirect key exchange. A dedicated-enclave partner rebuilds with their own URL,
# which changes the measurement — visibly, which is the point.
LABEL "tee.launch_policy.allow_env_override"="FID_ANTHROPIC_KEY,FID_IDENTITY_SEED"
EXPOSE 9090
ENTRYPOINT ["/app/fid-proxy"]
