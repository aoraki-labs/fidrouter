# Confidential Space workload image for YOUR enclave — reproducible by design.
#
# The image DIGEST is what Confidential Space attests, so anyone must be able to rebuild
# this source and get the same content. Hence: base pinned by digest, distroless static
# (deterministic, no shell, ships CA certs), and a reproducibly-built binary.
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
#     -ldflags=-buildid= -o enclave ./examples/enclave-template
#   docker buildx build --build-arg SOURCE_DATE_EPOCH=1700000000 \
#     --output type=image,name=<region>-docker.pkg.dev/<proj>/<repo>/<img>:v1,push=true,rewrite-timestamp=true .
#
FROM gcr.io/distroless/static-debian12@sha256:a9fcaedd4c9b59e12dd65d954f0b5044f19b0647a8a3712e77205df9e7b102cd
WORKDIR /app
COPY enclave /app/enclave
COPY config /app/config

# Baked = measured = provable. None of these is a secret, and pinning them in the image is
# the point: a verifier can see which CP key may authorise spend here and where metering goes,
# instead of taking the operator's word for it.
ENV FIDPROXY_ATTESTER=gcp-cs \
    FID_CS_AUDIENCE=fidrouter \
    ADDR=:9090
# ENV FID_CP_PUB=<your cp public key hex>
# ENV FIDPROXY_TLS=1 FIDPROXY_TLS_HOSTS=enclave.example.com

# ⚠️ ONLY the names listed here may be supplied as `tee-env-*` at launch. Anything else and
# the hardened Confidential Space launcher REFUSES to start the workload — the VM boots and
# terminates with no obvious error. Add a name here only if it must be operator-supplied AND
# is a secret; everything non-secret belongs in ENV above, where it gets measured.
LABEL "tee.launch_policy.allow_env_override"="FID_IDENTITY_SEED,FID_UPSTREAM_KEY"

EXPOSE 9090
ENTRYPOINT ["/app/enclave"]
