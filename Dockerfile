# Governance Layer (p3dx_gov_layer) — Go REST service on port 8083.
#
# Build:  docker build -t p3dx-gov-layer .
# Run:    docker run --env-file .env -p 8083:8083 \
#           -v "$PWD/keys:/app/keys" -v "$PWD/data:/app/data" p3dx-gov-layer
#
# .env is NOT baked into the image — pass it at runtime with --env-file.
# Set APD_BASE_URL to the hosted dev APD. Inside the container "localhost" is
# the container itself, so point DB_HOST at the host's Postgres (e.g.
# --network host, or host.docker.internal).

# ---- build stage ----
FROM golang:1.22-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gov-layer ./cmd/server

# ---- runtime stage ----
FROM debian:bookworm-slim

# python3: /final-model/inspect runs the embedded inspect_model.py (stdlib only).
# ca-certificates: HTTPS calls to Keycloak / catalogue / IUDX APD.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /app gov

WORKDIR /app
COPY --from=build /out/gov-layer /app/gov-layer

# keys/  — governance signing key (generated on first start; persist it, or
#          every new container signs contracts with a different key)
# data/  — STORE_PATH contracts.db for the legacy general-contract pathway
RUN mkdir -p /app/keys /app/data && chown -R gov:gov /app
USER gov

VOLUME ["/app/keys", "/app/data"]
# Approve TEE/SMPC jobs on the data-provider approval alone (no infra selected).
# Overridable at runtime (--env-file / -e REQUIRE_INFRA_APPROVAL=true).
ENV REQUIRE_INFRA_APPROVAL=false

EXPOSE 8083

ENTRYPOINT ["/app/gov-layer"]
