# P3DX Governance Layer (Go)

The **Governance Layer** is the coordination brain of the P3DX federated-learning
(FL) system. It stores the forms that Output Owners and Data Providers submit,
decides/records which providers participate in a session, renders and distributes
the FL client configuration, and orchestrates an FL round end-to-end
(provisioning Python environments and launching the FL server + clients through
the control-plane receivers). It also brokers the participation "consent"
messaging between owners and providers and persists a combined session report.

It speaks **REST** to the UI and the AAA backend, and **gRPC** to other backend
services, and it is backed by a **PostgreSQL** database (`p3dx_governance`).

> Ported from an original Node.js implementation to Go as a **drop-in
> replacement**: identical REST + gRPC endpoints, JSON shapes, status codes, the
> same `.env`, and the same `p3dx_governance` database. The original Node sources
> are kept under `src/` for reference only and are not used at runtime.

---

## What the Governance Layer is used for

- **Form storage** — persists Output Owner FL-config forms (`form_submissions`)
  and Data Provider registration forms (`data_provider_forms`).
- **Participation selection & consent** — records which providers an owner
  selected, and carries the notification loop: owner invites → provider
  accepts/declines (with a reason) → owner sees the responses → owner sends a
  final roster.
- **Config distribution** — renders `client_config.yaml` with the owner's
  reachable address and delivers it to each selected provider (HTTP push or scp).
- **FL orchestration** — provisions the venv on the owner and each provider, then
  starts the FL server, the FL session, and the clients, by calling the
  control-plane receivers.
- **Reporting** — assembles and stores a combined per-session report (owner
  config + selected providers + their resources) and serves it for download.

---

## Where it sits (architecture)

```
        ┌─────────────┐        ┌──────────────┐
        │  UI (React) │        │ AAA backend  │
        └──────┬──────┘        └──────┬───────┘
               │  HTTP (/api/v1, /governance)
               ▼                      ▼
        ┌──────────────────────────────────────────┐
        │        Governance Layer (this repo)       │
        │        REST :8084   ·   gRPC :50052        │
        └───┬───────────────┬──────────────┬────────┘
            │               │              │
            ▼               ▼              ▼
     PostgreSQL        Keycloak       FL receivers
   (p3dx_governance) (svc-account   owner env :8090
                      token for      providers :8080
                      receiver calls)
```

- **REST API** — port `8083` in code, set to `8084` in `.env`; used by the UI and
  AAA backend. Every route is mounted under **both** `/api/v1` and `/governance`.
- **gRPC server** — port `50052`; `GovernanceService` for backend-to-backend form
  operations.
- **PostgreSQL** — `p3dx_governance`; schema auto-created/migrated on startup.
- **Keycloak** — optional; provides a service-account token so gov_layer can
  authenticate to the FL receivers.
- **FL receivers** — small Python HTTP agents on the owner host (`:8090`,
  `output_owner_env_receiver.py`) and each provider (`:8080`,
  `provider_config_receiver.py`) that actually create venvs, write config, and
  launch `flo_server` / `flo_client`.

---

## End-to-end FL flow (through the Governance Layer)

1. **Providers advertise** — each Data Provider submits a registration form
   (`POST /data-provider-forms`) carrying its `ip_address`, `port`, RAM, RAM
   usage, disk and data size. This is stored in `data_provider_forms`.

2. **Owner configures & selects** — the Output Owner submits an FL config form
   (`POST /form-submissions`) that includes `selected_providers` (the chosen
   subset). Upserted on `form_id`, so re-submitting updates the same row/id.

3. **Consent loop (notifications)**
   - Owner invites the selected providers (`POST /notifications`, kind
     `participation_request`) — the message lists who was requested vs selected.
   - Each provider answers (`POST /notifications/:id/respond`) with
     `accepted`/`declined` plus an optional reason.
   - Owner reviews answers (`GET /notifications/by-sender/:username`) and can send
     a final roster (a second `participation_roster` notification).

4. **Config distribution** — gov renders `client_config.yaml` (injecting the
   owner's reachable IP as the MQTT broker host + gRPC host) and delivers it:
   - `POST /push-config` — HTTP-push to each provider's `:8080` receiver, or
   - `POST /distribute-config` — scp via `send_output_owner_config.sh`.
   - Providers can also pull it directly (`GET /client-config/:username`).

5. **Provisioning** — `POST /provision-env` creates the Python venv (and installs
   requirements) on each selected provider's receiver; `start-fl-session` also
   provisions the owner's venv.

6. **Start the round** — `POST /start-fl-session` orchestrates the whole bring-up:
   provision the owner env → start `flo_server` → start the FL session → provision
   + push config to providers → start their `flo_clients`. Timeouts/delays between
   steps are configurable.

7. **Report** — a combined session report (owner + selected providers) is built
   and stored (`session_reports`), downloadable via
   `GET /form-submissions/:id/report`.

---

## File-by-file reference

### Entry point
| File | Purpose |
|------|---------|
| `cmd/server/main.go` | Process entry point. Loads config, opens the DB (runs migrations), builds the Keycloak client, starts the **REST** server and the **gRPC** server, and handles graceful shutdown. |

### `internal/config` — configuration
| File | Purpose |
|------|---------|
| `config/config.go` | Loads all runtime config from the environment and the service's own `.env` (**override** semantics so a sibling service's exported vars can't hijack this one). Holds the `Config` struct: DB connection, ports, Keycloak settings, FL-orchestration paths/timeouts, and `OWNER_SELF_IPS`. Also derives the Keycloak token URL and the owner-receiver fallback URL. |

### `internal/db` — PostgreSQL data layer (pgx)
| File | Purpose |
|------|---------|
| `db/db.go` | Opens the connection pool, auto-creates the `p3dx_governance` database if missing, and runs idempotent **migrations** (all `CREATE TABLE` / `ALTER TABLE` for `form_submissions`, `data_provider_forms`, `notifications`, `session_reports`). |
| `db/types.go` | Custom JSON types: `Real` (emits shortest float32 decimal so JSON matches the Node output) and `BigInt` (int64 that serializes safely). |
| `db/helpers.go` | Shared helpers: `newID`/base36 id generation, `FlexFloat` (accepts string-or-number from the loosely-typed UI), and the `truthy*` / `jsonbOr` coercions used by inserts. |
| `db/forms.go` | Output-owner `form_submissions`: `FormSubmission`/`FormInput` structs, `StoreFormSubmission` (upsert on `form_id`), list/get/delete, `SelectedProviderList()`, and `GetLatestSessionForProvider` (used by the provider-side config pull). |
| `db/provider_forms.go` | Data-provider `data_provider_forms`: struct + input, `StoreDataProviderForm`, `GetAllDataProviderForms`, and `GetDataProviderFormsByUsernames` (latest form per provider — used to resolve each selected provider's ip/port/RAM). |
| `db/notifications.go` | The `notifications` table and the whole consent loop: `CreateNotification`, `GetNotificationsForUser`, `MarkNotificationAsRead`, `RespondToNotification` (accepted/declined + reason), and `GetNotificationsBySender` (owner's responses view). |
| `db/messages.go` | The mock `GetDataProviders` list and `StoreProviderMessage` (lazily-created `provider_messages` table for `/send-provider-message`). |
| `db/reports.go` | `StoreSessionReport` (upsert on `submission_id`) and `GetSessionReport` for the combined FL session report. |

### `internal/httpapi` — REST API + FL orchestration
| File | Purpose |
|------|---------|
| `httpapi/server.go` | Wires the router (chi), CORS, JSON helpers, and mounts **every** route under both `/api/v1` and `/governance`. Holds the `Server` (config + DB + Keycloak + self-IP set). |
| `httpapi/handlers.go` | Request handlers for forms, data-providers, provider messages, and notifications (create / list / read / **respond** / **by-sender**). Thin layer over the `db` package. |
| `httpapi/orchestration.go` | The FL control plane: render `client_config.yaml`, POST to receivers with auth + timeouts, fan out over selected providers in parallel (`provisionProviders`, `renderAndPushClientConfig`), provision the owner env, and tally per-target results. |
| `httpapi/report.go` | Builds the combined report (`buildCombinedReport`), resolves `selectedUsernames`, persists it after a session, and serves `GET …/report`. |
| `httpapi/selfip.go` | "This host" detection: seeds loopback + local interface IPs + `OWNER_SELF_IPS`, and `reachableHost()` rewrites a self IP to `127.0.0.1` (a VM can't reach its own public IP — Azure hairpin). Also discovers the public IP asynchronously. |

### `internal/keycloak` — service-account auth
| File | Purpose |
|------|---------|
| `keycloak/keycloak.go` | Fetches and caches a Keycloak service-account token (client-credentials grant) and builds the `Authorization` headers for calls to the FL receivers. Falls back to a static `PUSH_AUTH_TOKEN` when Keycloak isn't configured. |

### `internal/grpcsrv` — gRPC service
| File | Purpose |
|------|---------|
| `grpcsrv/server.go` | Implements `GovernanceService` on `:50052`: `SubmitForm`, `GetForm`, `GetAllForms`, `DeleteForm`, backed by the same `db` layer; maps between protobuf messages and DB structs. |

### `internal/govpb` — generated bindings
| File | Purpose |
|------|---------|
| `govpb/governance.pb.go`, `govpb/governance_grpc.pb.go` | **Generated** protobuf + gRPC code from `protos/governance.proto`. Do not edit by hand — regenerate (see below). |

### Other
| Path | Purpose |
|------|---------|
| `protos/` | `.proto` service/message definitions. |
| `.env.example` | Template for the runtime config (`.env` is gitignored — it holds secrets). |
| `go.mod` / `go.sum` | Go module + dependency checksums. |
| `src/` | Original Node.js implementation, retained for reference only. |

---

## Data model (tables, auto-migrated)

- **`form_submissions`** — output-owner FL config: hyperparameters, `model`,
  `framework`, `components`, `selected_providers` (JSONB), `ip_address`, `port`,
  `ram_usage`.
- **`data_provider_forms`** — provider registration: `data_owner_id`, `ram`,
  `ram_usage`, `memory_mb`, `data_size_bytes`, `data_resource_id`, `ip_address`,
  `port`.
- **`notifications`** — consent loop: `recipient_*`, `sender_username`, `message`,
  `payload` (JSONB, carries `kind`/`submission_id`/provider lists), `read`,
  `response` (`accepted`/`declined`), `response_message`.
- **`session_reports`** — combined per-session report (upsert on `submission_id`).
- **`provider_messages`** — free-form provider messages (lazily created).

---

## Configuration

Copy `.env.example` to `.env` and adjust. `.env` is loaded with **override**
semantics, so this service's values win over any inherited shell variables.

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | REST API port | `8083` |
| `GRPC_PORT` | gRPC port | `50052` |
| `NODE_ENV` | Environment label | `development` |
| `CORS_ORIGINS` | Comma-separated allowed origins | — |
| `DB_HOST`/`DB_PORT`/`DB_NAME`/`DB_USER`/`DB_PASSWORD` | PostgreSQL connection | `localhost`/`5432`/`p3dx_governance`/`postgres`/`postgres` |
| `KEYCLOAK_BASE_URL`/`KEYCLOAK_REALM`/`KEYCLOAK_CLIENT_ID`/`KEYCLOAK_CLIENT_SECRET` | Service-account auth for receiver calls | — |
| `PUSH_AUTH_TOKEN` | Legacy `X-Auth-Token` fallback when Keycloak is unset | — |
| `OWNER_SELF_IPS` | Extra IPs treated as "this host" (rewritten to loopback so gov reaches a co-located receiver locally) | — |

FL-orchestration paths/timeouts (`DISTRIBUTE_SCRIPT`, `PROVISION_TIMEOUT_MS`,
`PUSH_TIMEOUT_MS`, `FL_SESSION_DELAY_MS`, `CLIENT_CONFIG_TEMPLATE`, …) keep the
same names/defaults and can be overridden via the environment.

---

## API

All REST routes are mounted under **both** `/api/v1` and `/governance`.

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/form-submissions` | Store an Output Owner form (upsert on `form_id`) |
| `GET` | `/form-submissions` | List all submissions |
| `GET` | `/form-submissions/export` | Download all submissions as JSON |
| `GET` | `/form-submissions/:id` | Fetch one submission |
| `DELETE` | `/form-submissions/:id` | Delete one submission |
| `GET` | `/form-submissions/:id/report` | Download the combined FL session report |
| `GET` | `/data-providers` | Mock provider list |
| `POST` | `/send-provider-message` | Store a provider message |
| `POST` | `/data-provider-forms` | Store a Data Provider form |
| `GET` | `/data-provider-forms` | List Data Provider forms |
| `POST` | `/notifications` | Create notifications for recipients |
| `GET` | `/notifications/:username` | Fetch a user's notifications |
| `GET` | `/notifications/by-sender/:username` | Notifications a user sent (owner's responses view) |
| `PATCH` | `/notifications/:id/read` | Mark a notification read |
| `POST` | `/notifications/:id/respond` | Provider answers a request (`accepted`/`declined` + reason) |
| `POST` | `/distribute-config` | scp client config to providers (`send_output_owner_config.sh`) |
| `POST` | `/provision-env` | Provision a venv on each selected provider |
| `POST` | `/push-config` | HTTP-push rendered `client_config.yaml` to providers |
| `POST` | `/start-fl-session` | Bring up owner + providers and start the FL round |
| `GET` | `/client-config/by-submission/:id` | Owner-side rendered config download |
| `GET` | `/client-config/:username` | Provider-side rendered config pull |

**gRPC `GovernanceService`**: `SubmitForm`, `GetForm`, `GetAllForms`,
`DeleteForm` (see `protos/governance.proto`).

---

## Running

Requirements: Go 1.22+, PostgreSQL (db `p3dx_governance`, auto-created on first
run), and optionally Keycloak.

```bash

# to run keycloak 
bin/kc.sh start-dev

# from this directory (p3dx_gov_layer/)
go run ./cmd/server
```
PGPASSWORD="$(grep '^DB_PASSWORD=' /home/azureuserfl/fl_flow/p3dx_gov_layer/.env | cut -d= -f2-)" psql -h localhost -U p3dx_gov -d p3dx_governance -c "SELECT id, project_id, session_id, finalized, jsonb_pretty(contract) AS contract FROM contracts ORDER BY updated_at DESC;"

Or build a binary:

```bash
go build -o gov-layer ./cmd/server
./gov-layer
```

The repo's `../start.sh` launches the whole P3DX stack and starts this service
with `go run ./cmd/server`.

## Regenerating gRPC bindings

```bash
protoc -I protos \
  --go_out=internal/govpb --go_opt=paths=source_relative,Mgovernance.proto=github.com/s4r4v4n04/p3dx_gov_layer/internal/govpb \
  --go-grpc_out=internal/govpb --go-grpc_opt=paths=source_relative,Mgovernance.proto=github.com/s4r4v4n04/p3dx_gov_layer/internal/govpb \
  governance.proto
```
