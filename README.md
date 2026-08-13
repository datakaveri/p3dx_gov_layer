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
> same `.env`, and the same `p3dx_governance` database. The Node sources have
> since been removed — this repo is Go-only.

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
Files are prefixed `fl_` when the workflow they implement is FL-only; everything
else is infrastructure shared by whatever else the service grows into.

| File | Purpose |
|------|---------|
| `db/db.go` | Opens the connection pool, auto-creates the `p3dx_governance` database if missing, and runs idempotent **migrations** (`notifications`, `session_reports` — form storage now lives in APD, see below). |
| `db/types.go` | Custom JSON types: `Real` (emits shortest float32 decimal so JSON matches the Node output) and `BigInt` (int64 that serializes safely). |
| `db/helpers.go` | Shared helpers: `newID`/base36 id generation, `FlexFloat` (accepts string-or-number from the loosely-typed UI), and the `truthy*` / `jsonbOr` coercions used by inserts. |
| `db/apd_client.go` | HTTP client to APD, the store of record for FL forms (`APD_URL`). |
| `db/fl_forms.go` | Output-owner form: `FormSubmission`/`FormInput` structs and the store/list/get/delete methods, backed by APD via `apd_client.go`. |
| `db/fl_provider_forms.go` | Data-provider form: struct + input and its store/list methods, backed by APD. |
| `db/fl_notifications.go` | The `notifications` table and the whole consent loop: `CreateNotification`, `GetNotificationsForUser`, `MarkNotificationAsRead`, `RespondToNotification` (accepted/declined + reason), and `GetNotificationsBySender` (owner's responses view). |
| `db/fl_messages.go` | The mock `GetDataProviders` list and `StoreProviderMessage` (lazily-created `provider_messages` table for `/send-provider-message`). |
| `db/fl_reports.go` | `StoreSessionReport` (upsert on `submission_id`) and `GetSessionReport` for the combined FL session report. |
| `db/contracts.go` | The per-session FL contract in the standard contract JSON format (`project_id`, `lifecycle`, `parties`, `session_info`, `signatures`). Signing is not implemented yet — `signatures` is emitted empty. |

### `internal/httpapi` — REST API + FL orchestration
Same `fl_` convention as above.

| File | Purpose |
|------|---------|
| `httpapi/server.go` | Wires the router (chi), CORS, JSON helpers, and mounts **every** route under both `/api/v1` and `/governance`. Holds the `Server` (config + DB + Keycloak + self-IP set). |
| `httpapi/fl_forms.go` | Request handlers for forms, data-providers, and provider messages. Thin layer over the `db` package. |
| `httpapi/fl_notifications.go` | Request handlers for notifications (create / list / read / **respond** / **by-sender**). |
| `httpapi/fl_orchestration.go` | The FL control plane: render `client_config.yaml`, POST to receivers with auth + timeouts, fan out over selected providers in parallel (`provisionProviders`, `renderAndPushClientConfig`), provision the owner env, and tally per-target results. |
| `httpapi/fl_report.go` | Builds the combined report (`buildCombinedReport`), resolves `selectedUsernames`, persists it after a session, and serves `GET …/report`. |
| `httpapi/fl_selfip.go` | "This host" detection: seeds loopback + local interface IPs + `OWNER_SELF_IPS`, and `reachableHost()` rewrites a self IP to `127.0.0.1` (a VM can't reach its own public IP — Azure hairpin). Also discovers the public IP asynchronously. |
| `httpapi/contracts.go` | `POST /contracts` / `GET /contracts/{sessionId}` — assembles and stores the per-session contract (`db/contracts.go`), called by the AAA layer. |
| `httpapi/model.go`, `httpapi/inspect_model.py` | `GET /final-models`, `/final-model/download`, `/final-model/summary` — locates flo_server's per-round checkpoints in `CHECKPOINT_DIR` and summarises the highest-round one via the embedded, torch-free `.pt` reader script. |

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

---

## Data model (tables, auto-migrated)

Output-owner and data-provider forms are **not** local tables anymore — APD is
their store of record (`APD_URL`, see `db/apd_client.go`); this service just
owns the struct shapes and forwards reads/writes over HTTP.

- **`notifications`** — consent loop: `recipient_*`, `sender_username`, `message`,
  `payload` (JSONB, carries `kind`/`submission_id`/provider lists), `read`,
  `response` (`accepted`/`declined`), `response_message`.
- **`session_reports`** — combined per-session report (upsert on `submission_id`).
- **`contracts`** — the per-session FL contract: `project_id`, `session_id`
  (unique), `output_owner_id`, `finalized`, and the full contract document
  (`contract` JSONB, in the standard `project_id`/`lifecycle`/`parties`/
  `session_info`/`signatures` shape — see `db/contracts.go`).
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

All REST routes are mounted under **both** `/api/v1` and `/governance` (CORS enabled, flexible origins).

### Two Contract Pathways

The governance layer supports two distinct contract pathways:

1. **FL Pathway** — Forms-based contract assembly with sequential orchestration
2. **General Pathway** — Pre-built contracts with policy authorization and immediate TEE deployment

### REST Endpoints

#### Forms & Providers (FL-Specific)

| Method | Path | Purpose | Pathway |
|--------|------|---------|---------|
| `POST` | `/form-submissions` | Store an Output Owner FL config form (upsert on `form_id`) | FL |
| `GET` | `/form-submissions` | List all form submissions | FL |
| `GET` | `/form-submissions/export` | Download all submissions as JSON | FL |
| `GET` | `/form-submissions/:id` | Fetch one form submission | FL |
| `DELETE` | `/form-submissions/:id` | Delete one form submission | FL |
| `GET` | `/data-providers` | List registered data providers | FL |
| `POST` | `/send-provider-message` | Send a message to a data provider | FL |
| `POST` | `/data-provider-forms` | Store a Data Provider registration form | FL |
| `GET` | `/data-provider-forms` | List all data provider forms | FL |

#### Notifications & Consent (FL-Specific)

| Method | Path | Purpose | Pathway |
|--------|------|---------|---------|
| `POST` | `/notifications` | Create participation-request notifications | FL |
| `GET` | `/notifications/:username` | Fetch notifications for a user | FL |
| `GET` | `/notifications/by-sender/:username` | Fetch notifications sent by a user | FL |
| `PATCH` | `/notifications/:id/read` | Mark a notification as read | FL |
| `POST` | `/notifications/:id/respond` | Provider responds to a notification (`accepted`/`declined` + reason) | FL |

#### Contracts (Both Pathways)

| Method | Path | Purpose | Pathway |
|--------|------|---------|---------|
| `POST` | `/contracts` | Assemble contract from form submission data (draft or final) | FL |
| `GET` | `/contracts/:sessionId` | Retrieve contract for a session | FL |
| `POST` | `/contract` | Submit pre-built contract (validates token, verifies signature, authorizes via APD, signs with orchestrator key, deploys to TEE) | GENERAL |

#### Reporting & Models

| Method | Path | Purpose | Pathway |
|--------|------|---------|---------|
| `GET` | `/form-submissions/:id/report` | Download the combined FL session report (metrics, participants, training config) | FL |
| `GET` | `/final-models` | List final (highest-round) models for all sessions | BOTH |
| `GET` | `/final-model/download` | Download a final model checkpoint file (.pt or .weights) | BOTH |
| `GET` | `/final-model/summary` | Get JSON summary of model architecture (layers, parameters, etc.) | BOTH |

#### FL Orchestration (FL-Specific)

| Method | Path | Purpose | Pathway |
|--------|------|---------|---------|
| `POST` | `/distribute-config` | Distribute client_config.yaml to providers via SCP | FL |
| `POST` | `/provision-env` | Provision Python virtual environments on selected providers | FL |
| `POST` | `/push-config` | HTTP-push rendered client_config.yaml to providers | FL |
| `POST` | `/start-fl-session` | Complete FL orchestration in one call: owner env → server → provider envs → config → clients → session | FL |
| `GET` | `/client-config/by-submission/:id` | Retrieve rendered client config for a form submission | FL |
| `GET` | `/client-config/:username` | Retrieve rendered client config for a provider (pulled during setup) | FL |

#### Internal Endpoints (Server-to-Server, Not Public)

These are called by AAA (authentication & authorization service) to push form updates into the governance layer's local cache. **Not accessible via `/api/v1` or `/governance`.**

| Method | Path | Purpose | Access |
|--------|------|---------|--------|
| `POST` | `/internal/forms/submissions` | Ingest form submission from AAA (store of record) | Internal only |
| `DELETE` | `/internal/forms/submissions/:id` | Delete form submission from local cache | Internal only |
| `POST` | `/internal/forms/provider-forms` | Ingest data provider form from AAA | Internal only |

### gRPC API

**Service**: `GovernanceService` (port `50052`; see `protos/governance.proto`)

| Method | Request | Response | Purpose |
|--------|---------|----------|---------|
| `SubmitForm` | `FormSubmission` | `SubmissionResponse` | Create a form submission |
| `GetForm` | `GetFormRequest` | `FormSubmission` | Retrieve a form by ID |
| `GetAllForms` | `GetAllFormsRequest` | `GetAllFormsResponse` | List all forms |
| `DeleteForm` | `DeleteFormRequest` | `DeleteResponse` | Delete a form by ID |

### Contract Pathway Details

**FL Pathway Flow:**
1. Create form submission (owner config + selected providers)
2. Build initial contract (particiption request, `finalize=false`)
3. Send notifications to providers
4. Wait for provider responses
5. Build final contract (confirmed roster, `finalize=true`)
6. Orchestrate: distribute config → provision envs → push config → start clients → start session
7. Retrieve final models and report

**General Pathway Flow:**
1. Build contract externally (arbitrary `compute_choice`, `execution_platform`)
2. Get user's Keycloak token
3. Sign contract with user's private key
4. POST to `/contract` with signed contract
5. Governance layer validates token, verifies signature, authorizes against APD policies, stores securely, signs with orchestrator key, deploys to TEE immediately
6. Retrieve results from TEE (outside governance layer scope)

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
