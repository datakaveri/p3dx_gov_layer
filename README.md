# P3DX Governance Layer (Go)

The **Governance Layer** is the coordination brain of the P3DX federated-learning
(FL) system. It manages participation consent and contracts between output owners
and data providers. Forms are created and stored in **aaa** (the FL form UI backend)
and also persisted in **APD** (Access Policy Database).

It speaks **REST** to the UI and aaa, and it is backed by a **PostgreSQL**
database (`p3dx_governance`).

> Ported from an original Node.js implementation to Go as a **drop-in
> replacement**: identical REST endpoints, JSON shapes, status codes, the
> same `.env`, and the same `p3dx_governance` database. The Node sources have
> since been removed — this repo is Go-only. Form storage has moved to aaa and
> APD; form orchestration has been removed from this service.

---

## What the Governance Layer is used for

- **Participation selection & consent** — records which providers an owner
  selected, and carries the notification loop: owner invites → provider
  accepts/declines (with a reason) → owner sees the responses → owner sends a
  final roster.
- **Contract management** — assembles and stores contracts for FL sessions.

---

## Where it sits (architecture)

```
        ┌─────────────┐        ┌──────────────┐        ┌─────────┐
        │  UI (React) │        │     aaa      │        │   APD   │
        └──────┬──────┘        └──────┬───────┘        └────┬────┘
               │ HTTP             │ forms created/      │ forms
               │                  │ stored here         │ persisted
               ▼                  ▼                     ▼
        ┌──────────────────────────────────────────────────────────┐
        │     Governance Layer (this repo)                          │
        │        REST :8083 (UI, contracts, notifications)          │
        └──────────────────────────────────────────────────────────┘
                 │
                 ▼
           PostgreSQL
        (p3dx_governance)
```

- **REST API** — port `8083` in code, set to `8084` in `.env`; used by the UI
  and aaa. Every route is mounted under **both** `/api/v1` and `/governance`.
- **PostgreSQL** — `p3dx_governance`; schema auto-created/migrated on startup
  (notifications, session_reports, contracts tables).
- **APD** — Access Policy Database where forms are persisted in PostgreSQL.

---

## Participation & Consent Flow

1. **Forms submitted** — Output Owners and Data Providers submit their forms to
   **aaa** (the FL form UI backend). aaa stores forms in immudb and also sends
   them to **APD** for persistence and policy checks.

2. **Consent loop (notifications)**
   - Owner invites selected providers (`POST /notifications`, kind
     `participation_request`) — lists requested vs selected providers.
   - Each provider answers (`POST /notifications/:id/respond`) with
     `accepted`/`declined` plus an optional reason.
   - Owner reviews answers (`GET /notifications/by-sender/:username`) and can send
     a final roster (a second `participation_roster` notification).

3. **Contract management** — contracts are assembled and stored for record-keeping
   (`POST /contracts`, `GET /contracts/:sessionId`).

---

## File-by-file reference

### Entry point
| File | Purpose |
|------|---------|
| `cmd/server/main.go` | Process entry point. Loads config, opens the DB (runs migrations), builds the Keycloak client, starts the **REST** server, and handles graceful shutdown. |

### `internal/config` — configuration
| File | Purpose |
|------|---------|
| `config/config.go` | Loads all runtime config from the environment and the service's own `.env` (**override** semantics so a sibling service's exported vars can't hijack this one). Holds the `Config` struct: DB connection, ports, and Keycloak settings. |

### `internal/db` — PostgreSQL data layer (pgx)
| File | Purpose |
|------|---------|
| `db/db.go` | Opens the connection pool, auto-creates the `p3dx_governance` database if missing, and runs idempotent **migrations** (`notifications`, `contracts`). |
| `db/types.go` | Custom JSON types: `Real` (emits shortest float32 decimal so JSON matches the Node output) and `BigInt` (int64 that serializes safely). |
| `db/helpers.go` | Shared helpers: `newID`/base36 id generation and the `jsonbOr` coercion used by inserts. |
| `db/forms_cache.go` | In-memory cache of forms pushed here by aaa (`formsCache`) — no HTTP calls, no persistence. Read by the methods below; written only by `httpapi/forms_ingest.go`. |
| `db/fl_forms.go` | Output-owner form: the `FormSubmission` struct and `GetFormSubmissionByID`/`GetLatestSessionForProvider`/`IngestFormSubmission`/`RemoveFormSubmission`, all backed by `forms_cache.go`. |
| `db/fl_provider_forms.go` | Data-provider form: the `DataProviderForm` struct and `GetDataProviderFormsByUsernames`/`IngestDataProviderForm`, backed by `forms_cache.go`. |
| `db/fl_notifications.go` | The `notifications` table and the whole consent loop: `CreateNotification`, `GetNotificationsForUser`, `MarkNotificationAsRead`, `RespondToNotification` (accepted/declined + reason), and `GetNotificationsBySender` (owner's responses view). |
| `db/fl_messages.go` | The mock `GetDataProviders` list and `StoreProviderMessage` (lazily-created `provider_messages` table for `/send-provider-message`). |
| `db/contracts.go` | The per-session FL contract in the standard contract JSON format (`project_id`, `lifecycle`, `parties`, `session_info`, `signatures`). Signing is not implemented yet — `signatures` is emitted empty. |

### `internal/httpapi` — REST API
| File | Purpose |
|------|---------|
| `httpapi/server.go` | Wires the router (chi), CORS, JSON helpers, and mounts **every** route under both `/api/v1` and `/governance`. Holds the `Server` (config + DB + Keycloak). |
| `httpapi/fl_forms.go` | Request handlers for the mock provider directory and provider messages. |
| `httpapi/fl_notifications.go` | Request handlers for notifications (create / list / read / **respond** / **by-sender**). |
| `httpapi/contracts.go` | `POST /contracts` / `GET /contracts/{sessionId}` — assembles and stores the per-session contract. |
| `httpapi/model.go`, `httpapi/inspect_model.py` | `GET /final-models`, `/final-model/download`, `/final-model/summary` — locates flo_server's per-round checkpoints in `CHECKPOINT_DIR` and summarises the highest-round one via the embedded, torch-free `.pt` reader script. |

### `internal/keycloak` — optional service-account auth
| File | Purpose |
|------|---------|
| `keycloak/keycloak.go` | Optionally fetches and caches a Keycloak service-account token (client-credentials grant). Falls back to a static `PUSH_AUTH_TOKEN` when Keycloak isn't configured. |

### Other
| Path | Purpose |
|------|---------|
| `.env.example` | Template for the runtime config (`.env` is gitignored — it holds secrets). |
| `go.mod` / `go.sum` | Go module + dependency checksums. |

---

## Data model (tables, auto-migrated)

- **`notifications`** — consent loop: `recipient_*`, `sender_username`, `message`,
  `payload` (JSONB, carries `kind`/`submission_id`/provider lists), `read`,
  `response` (`accepted`/`declined`), `response_message`.
- **`contracts`** — the per-session FL contract: `project_id`, `session_id`
  (unique), `output_owner_id`, `finalized`, and the full contract document
  (`contract` JSONB, in the standard `project_id`/`lifecycle`/`parties`/
  `session_info`/`signatures` shape).
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
| `KEYCLOAK_BASE_URL`/`KEYCLOAK_REALM`/`KEYCLOAK_CLIENT_ID`/`KEYCLOAK_CLIENT_SECRET` | Keycloak service-account auth (optional) | — |
| `PUSH_AUTH_TOKEN` | Legacy `X-Auth-Token` fallback when Keycloak is unset | — |

---

## API

All REST routes are mounted under **both** `/api/v1` and `/governance`.

| Method | Path | Purpose |
|--------|------|---------|
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/data-providers` | Mock provider list |
| `POST` | `/send-provider-message` | Store a provider message |
| `POST` | `/notifications` | Create notifications for recipients |
| `GET` | `/notifications/:username` | Fetch a user's notifications |
| `GET` | `/notifications/by-sender/:username` | Notifications a user sent (owner's responses view) |
| `PATCH` | `/notifications/:id/read` | Mark a notification read |
| `POST` | `/notifications/:id/respond` | Provider answers a request (`accepted`/`declined` + reason) |
| `POST` | `/contracts` | Assemble and store a contract for a session |
| `GET` | `/contracts/:sessionId` | Retrieve a contract by session |
| `GET` | `/final-models` | List final models |
| `GET` | `/final-model/download` | Download a final model |
| `GET` | `/final-model/summary` | Summarize a final model |

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
