# P3DX Governance Layer (Go)

A Go backend service for the P3DX system. It stores Output Owner and Data
Provider form submissions, distributes federated-learning client configuration,
and orchestrates FL sessions (provisioning + launching server/clients via the
control-plane receivers).

> This service was ported from the original Node.js implementation to Go. It is
> a **drop-in replacement**: identical REST + gRPC endpoints, identical JSON
> shapes/status codes, the same `.env`, and the same `p3dx_governance` PostgreSQL
> database. No behaviour or usability changes — the FL flow works exactly as
> before. The original Node sources are retained under `src/` for reference but
> are no longer used at runtime.

## Architecture

```
AAA Backend / UI ──HTTP──> Governance Layer  (:8084 REST, :50052 gRPC)
                                  │
                                  ├── PostgreSQL  (p3dx_governance)
                                  ├── Keycloak    (service-account token for receiver calls)
                                  └── FL receivers (owner :8090 / providers :8080)
```

The service exposes:
1. **REST API** (port `8083`, set to `8084` in `.env`) for the frontend and AAA backend.
2. **gRPC server** (port `50052`) for backend-to-backend communication (`GovernanceService`).

## Requirements

- Go 1.22+
- PostgreSQL (database `p3dx_governance`; auto-created on first run if missing)
- (optional) Keycloak, for service-account auth on calls to the FL receivers

## Configuration

Copy `.env.example` to `.env` and adjust. The service loads `.env` with
**override** semantics (its own values win over any inherited shell variables),
so generic vars like `DB_USER`/`DB_PASSWORD` exported for a sibling service can't
hijack this one's database connection.

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | REST API port | `8083` |
| `GRPC_PORT` | gRPC port | `50052` |
| `NODE_ENV` | Environment label | `development` |
| `CORS_ORIGINS` | Comma-separated allowed origins (informational) | — |
| `DB_HOST`/`DB_PORT`/`DB_NAME`/`DB_USER`/`DB_PASSWORD` | PostgreSQL connection | `localhost`/`5432`/`p3dx_governance`/`postgres`/`postgres` |
| `KEYCLOAK_BASE_URL`/`KEYCLOAK_REALM`/`KEYCLOAK_CLIENT_ID`/`KEYCLOAK_CLIENT_SECRET` | Service-account auth for receiver calls | — |
| `PUSH_AUTH_TOKEN` | Legacy `X-Auth-Token` fallback when Keycloak is unset | — |
| `OWNER_SELF_IPS` | Extra IPs treated as "this host" (rewritten to loopback) | — |

FL-orchestration paths/timeouts (`DISTRIBUTE_SCRIPT`, `PROVISION_TIMEOUT_MS`,
`PUSH_TIMEOUT_MS`, `FL_SESSION_DELAY_MS`, `CLIENT_CONFIG_TEMPLATE`, …) keep the
same names and defaults as before and can be overridden via the environment.

## Running

```bash
# from this directory (p3dx_gov_layer/)
go run ./cmd/server
PORT=8090 ./output_owner_env_receiver.py
```
  
Or build a binary:

```bash
go build -o gov-layer ./cmd/server
./gov-layer
```

The repo's `../start.sh` launches the whole P3DX stack and starts this service
with `go run ./cmd/server`.

## API Endpoints

All endpoints are mounted under **both** `/api/v1` and `/governance`.

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/form-submissions` | Store an Output Owner form (upsert on `form_id`) |
| `GET` | `/form-submissions` | List all submissions |
| `GET` | `/form-submissions/export` | Download all submissions as JSON |
| `GET` | `/form-submissions/:id` | Fetch one submission |
| `DELETE` | `/form-submissions/:id` | Delete one submission |
| `GET` | `/form-submissions/:id/report` | Download the combined FL session report (JSON) |
| `GET` | `/data-providers` | Mock provider list |
| `POST` | `/send-provider-message` | Store a provider notification message |
| `POST` | `/data-provider-forms` | Store a Data Provider form |
| `GET` | `/data-provider-forms` | List Data Provider forms |
| `POST` | `/notifications` | Create notifications for recipients |
| `GET` | `/notifications/:username` | Fetch a user's notifications |
| `GET` | `/notifications/by-sender/:username` | Notifications a user sent (owner's participation-responses view) |
| `PATCH` | `/notifications/:id/read` | Mark a notification read |
| `POST` | `/notifications/:id/respond` | Provider answers a participation request (`accepted`/`declined` + reason) |
| `POST` | `/distribute-config` | scp client config to providers (via `send_output_owner_config.sh`) |
| `POST` | `/provision-env` | Provision a venv on each selected provider |
| `POST` | `/push-config` | HTTP-push rendered `client_config.yaml` to providers |
| `POST` | `/start-fl-session` | Bring up owner + providers and start the FL round |
| `GET` | `/client-config/by-submission/:id` | Owner-side rendered config download |
| `GET` | `/client-config/:username` | Provider-side rendered config pull |

The gRPC `GovernanceService` provides `SubmitForm`, `GetForm`, `GetAllForms`,
`DeleteForm` (see `protos/governance.proto`).

## Project Structure

```
p3dx_gov_layer/
├── cmd/server/            # entry point (REST + gRPC, graceful shutdown)
├── internal/
│   ├── config/            # env loading + all route constants
│   ├── db/                # pgx data layer (schema, migrations, queries)
│   ├── keycloak/          # service-account token provider
│   ├── httpapi/           # REST handlers, CORS, FL orchestration, YAML render
│   ├── grpcsrv/           # gRPC GovernanceService
│   └── govpb/             # generated protobuf/gRPC bindings
├── protos/                # .proto definitions
├── go.mod / go.sum
├── .env.example
└── src/                   # original Node.js implementation (reference only)
```

## Regenerating gRPC bindings

```bash
protoc -I protos \
  --go_out=internal/govpb --go_opt=paths=source_relative,Mgovernance.proto=github.com/s4r4v4n04/p3dx_gov_layer/internal/govpb \
  --go-grpc_out=internal/govpb --go-grpc_opt=paths=source_relative,Mgovernance.proto=github.com/s4r4v4n04/p3dx_gov_layer/internal/govpb \
  governance.proto
```
