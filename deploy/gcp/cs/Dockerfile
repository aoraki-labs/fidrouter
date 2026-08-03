# Confidential Space workload image for fid-router.
# The image DIGEST is what Confidential Space attests (submods.container.image_digest),
# so this image IS the measured no-log data plane. Build context must contain:
#   fid-proxy  mock-upstream  entrypoint.sh  config/ (keys.json + pool.plain.json)
# Binaries are static (CGO_ENABLED=0), so a slim base is fine.
FROM debian:12-slim
WORKDIR /app
# CA roots so the enclave can verify the upstream TLS cert (api.anthropic.com);
# debian:12-slim ships without them.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY fid-proxy mock-upstream entrypoint.sh /app/
COPY config /app/config
RUN chmod +x /app/fid-proxy /app/mock-upstream /app/entrypoint.sh
ENV FIDPROXY_ATTESTER=gcp-cs \
    FID_HOME=/app/config \
    FIDPROXY_POOL_PLAINTEXT=/app/config/pool.plain.json \
    UPSTREAM_URL=http://127.0.0.1:9101/call \
    FIDPROXY_ADDR=:9090 \
    FID_CS_AUDIENCE=fid-router
# Confidential Space refuses operator env-var overrides unless the image allow-lists
# them. This permits the BYOK upstream key to be injected via `tee-env-FID_ANTHROPIC_KEY`
# metadata at launch — keeping it out of the image layers while the measured digest
# stays independent of the key value.
LABEL "tee.launch_policy.allow_env_override"="FID_ANTHROPIC_KEY,FID_IDENTITY_SEED"
EXPOSE 9090
ENTRYPOINT ["/app/entrypoint.sh"]
