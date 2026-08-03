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
ENV FIDPROXY_ATTESTER=gcp-cs \
    FID_HOME=/app/config \
    FIDPROXY_POOL_PLAINTEXT=/app/config/pool.plain.json \
    FIDPROXY_ADDR=:9090 \
    FID_CS_AUDIENCE=fidrouter
LABEL "tee.launch_policy.allow_env_override"="FID_ANTHROPIC_KEY,FID_IDENTITY_SEED"
EXPOSE 9090
ENTRYPOINT ["/app/fid-proxy"]
