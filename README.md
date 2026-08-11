# P3DX Governance Layer (Go)

The **Governance Layer** is the coordination brain of the P3DX federated-learning
(FL) system. Output Owners and Data Providers submit their forms to **aaa**, not
here — aaa pushes each one to the governance layer as it's created, and this
service keeps a local, in-memory copy to drive everything downstream: deciding
which providers participate in a session, rendering and distributing the FL
client configuration, and orchestrating an FL round end-to-end (provisioning
Python environments and launching the FL server + clients through the
control-plane receivers). It also brokers the participation "consent" messaging
between owners and providers and persists a combined session report.

It speaks **REST** to the UI and aaa, and it is backed by a **PostgreSQL**
database (`p3dx_governance`).

> Ported from an original Node.js implementation to Go as a **drop-in
> replacement**: identical REST endpoints, JSON shapes, status codes, the
> same `.env`, and the same `p3dx_governance` database. The Node sources have
> since been removed — this repo is Go-only. Form storage (and the gRPC
> `GovernanceService` that used to front it) has since moved to aaa; see
> "Where forms live" below.

---

## What the Governance Layer is used for

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

## Where forms live

Output-owner and data-provider forms are created and stored entirely in **aaa**
(immudb) — this service has no form CRUD at all. What it does have:

- `POST /internal/forms/submissions` / `POST /internal/forms/provider-forms` —
  aaa pushes each form here right after storing it (best-effort on aaa's side).
- `DELETE /internal/forms/submissions/{id}` — aaa pushes a delete the same way.
- An in-memory cache (`db/forms_cache.go`) holding whatever's been pushed so
  far, read by FL orchestration/reports/contracts (`GetFormSubmissionByID`,
  `GetLatestSessionForProvider`, `GetDataProviderFormsByUsernames`).

The cache is **not** a form store in its own right and has no backfill: on
restart it's empty until aaa pushes again (which happens on the next form
create/update). See `internal/httpapi/forms_ingest.go`.

---

## Where it sits (architecture)

```
        ┌─────────────┐        ┌──────────────┐
        │  UI (React) │        │     aaa      │
        └──────┬──────┘        └──────┬───────┘
               │  HTTP (/api/v1,      │  forms created/stored
               │        /governance)  │  here; pushed to gov layer
               ▼                      ▼  (/internal/forms/*)
        ┌──────────────────────────────────────────┐
        │        Governance Layer (this repo)       │
        │              REST :8084                   │
        └───┬───────────────┬──────────────┬────────┘
            │               │              │
            ▼               ▼              ▼
     PostgreSQL        Keycloak       FL receivers
   (p3dx_governance) (svc-account   owner env :8090
                      token for      providers :8080
                      receiver calls)
```

- **REST API** — port `8083` in code, set to `8084` in `.env`; used by the UI and
  aaa. Every route is mounted under **both** `/api/v1` and `/governance`; the
  forms-push endpoints are mounted separately under `/internal/forms`.
- **PostgreSQL** — `p3dx_governance`; schema auto-created/migrated on startup.
- **Keycloak** — optional; provides a service-account token so gov_layer can
  authenticate to the FL receivers.
- **FL receivers** — small Python HTTP agents on the owner host (`:8090`,
  `output_owner_env_receiver.py`) and each provider (`:8080`,
  `provider_config_receiver.py`) that actually create venvs, write config, and
  launch `flo_server` / `flo_client`.

---

## End-to-end FL flow (through the Governance Layer)

1. **Providers advertise** — each Data Provider submits a registration form to
   **aaa**, carrying its `ip_address`, `port`, RAM, RAM usage, disk and data
   size. aaa stores it and pushes it here (`POST /internal/forms/provider-forms`).

2. **Owner configures & selects** — the Output Owner submits an FL config form
   to **aaa**, which includes `selected_providers` (the chosen subset) — upserted
   on `form_id`, so re-submitting updates the same id — and pushes it here
   (`POST /internal/forms/submissions`).

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
| `cmd/server/main.go` | Process entry point. Loads config, opens the DB (runs migrations), builds the Keycloak client, starts the **REST** server, and handles graceful shutdown. |

### `internal/config` — configuration
| File | Purpose |
|------|---------|
| `config/config.go` | Loads all runtime config from the environment and the service's own `.env` (**override** semantics so a sibling service's exported vars can't hijack this one). Holds the `Config` struct: DB connection, ports, Keycloak settings, FL-orchestration paths/timeouts, and `OWNER_SELF_IPS`. Also derives the Keycloak token URL and the owner-receiver fallback URL. |

### `internal/db` — PostgreSQL data layer (pgx)
Files are prefixed `fl_` when the workflow they implement is FL-only; everything
else is infrastructure shared by whatever else the service grows into.

| File | Purpose |
|------|---------|
| `db/db.go` | Opens the connection pool, auto-creates the `p3dx_governance` database if missing, and runs idempotent **migrations** (`notifications`, `session_reports` — form storage lives in aaa, see "Where forms live" above). |
| `db/types.go` | Custom JSON types: `Real` (emits shortest float32 decimal so JSON matches the Node output) and `BigInt` (int64 that serializes safely). |
| `db/helpers.go` | Shared helpers: `newID`/base36 id generation and the `jsonbOr` coercion used by inserts. |
| `db/forms_cache.go` | In-memory cache of forms pushed here by aaa (`formsCache`) — no HTTP calls, no persistence. Read by the methods below; written only by `httpapi/forms_ingest.go`. |
| `db/fl_forms.go` | Output-owner form: the `FormSubmission` struct and `GetFormSubmissionByID`/`GetLatestSessionForProvider`/`IngestFormSubmission`/`RemoveFormSubmission`, all backed by `forms_cache.go`. |
| `db/fl_provider_forms.go` | Data-provider form: the `DataProviderForm` struct and `GetDataProviderFormsByUsernames`/`IngestDataProviderForm`, backed by `forms_cache.go`. |
| `db/fl_notifications.go` | The `notifications` table and the whole consent loop: `CreateNotification`, `GetNotificationsForUser`, `MarkNotificationAsRead`, `RespondToNotification` (accepted/declined + reason), and `GetNotificationsBySender` (owner's responses view). |
| `db/fl_messages.go` | The mock `GetDataProviders` list and `StoreProviderMessage` (lazily-created `provider_messages` table for `/send-provider-message`). |
| `db/fl_reports.go` | `StoreSessionReport` (upsert on `submission_id`) and `GetSessionReport` for the combined FL session report. |
| `db/contracts.go` | The per-session FL contract in the standard contract JSON format (`project_id`, `lifecycle`, `parties`, `session_info`, `signatures`). Signing is not implemented yet — `signatures` is emitted empty. |

### `internal/httpapi` — REST API + FL orchestration
Same `fl_` convention as above.

| File | Purpose |
|------|---------|
| `httpapi/server.go` | Wires the router (chi), CORS, JSON helpers, and mounts **every** route under both `/api/v1` and `/governance`, plus `/internal/forms` for aaa's pushes. Holds the `Server` (config + DB + Keycloak + self-IP set). |
| `httpapi/forms_ingest.go` | Receives aaa's form pushes (`POST/DELETE /internal/forms/...`) and writes them into `db/forms_cache.go`. Optionally guarded by `FORMS_PUSH_TOKEN`. |
| `httpapi/fl_forms.go` | Request handlers for the mock provider directory and provider messages. Thin layer over the `db` package — no form handlers live here. |
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

### Other
| Path | Purpose |
|------|---------|
| `.env.example` | Template for the runtime config (`.env` is gitignored — it holds secrets). |
| `go.mod` / `go.sum` | Go module + dependency checksums. |

---

## Data model (tables, auto-migrated)

Output-owner and data-provider forms are not local tables — aaa is their store
of record; this service only keeps an in-memory cache of what aaa pushes it
(see "Where forms live" above).

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
| `NODE_ENV` | Environment label | `development` |
| `CORS_ORIGINS` | Comma-separated allowed origins | — |
| `DB_HOST`/`DB_PORT`/`DB_NAME`/`DB_USER`/`DB_PASSWORD` | PostgreSQL connection | `localhost`/`5432`/`p3dx_governance`/`postgres`/`postgres` |
| `KEYCLOAK_BASE_URL`/`KEYCLOAK_REALM`/`KEYCLOAK_CLIENT_ID`/`KEYCLOAK_CLIENT_SECRET` | Service-account auth for receiver calls | — |
| `PUSH_AUTH_TOKEN` | Legacy `X-Auth-Token` fallback when Keycloak is unset | — |
| `OWNER_SELF_IPS` | Extra IPs treated as "this host" (rewritten to loopback so gov reaches a co-located receiver locally) | — |
| `FORMS_PUSH_TOKEN` | Shared secret aaa must send as `X-Forms-Push-Token` on `/internal/forms/*`; blank skips the check | — |

FL-orchestration paths/timeouts (`DISTRIBUTE_SCRIPT`, `PROVISION_TIMEOUT_MS`,
`PUSH_TIMEOUT_MS`, `FL_SESSION_DELAY_MS`, `CLIENT_CONFIG_TEMPLATE`, …) keep the
same names/defaults and can be overridden via the environment.

---

## API

All REST routes are mounted under **both** `/api/v1` and `/governance`.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/form-submissions/:id/report` | Download the combined FL session report |
| `GET` | `/data-providers` | Mock provider list |
| `POST` | `/send-provider-message` | Store a provider message |
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

Separately, under `/internal/forms` (not part of `/api/v1`/`/governance`, no
CORS, server-to-server only — see "Where forms live" above):

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/internal/forms/submissions` | aaa pushes an output-owner submission |
| `DELETE` | `/internal/forms/submissions/:id` | aaa pushes a submission delete |
| `POST` | `/internal/forms/provider-forms` | aaa pushes a data-provider form |

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
