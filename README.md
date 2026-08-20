# P3DX Governance Layer (Go)

The **Governance Layer** is the coordination brain of the P3DX system. It receives
contracts specifying a technique (FL, TEE, or SMPC) and selected datasets, fetches
the necessary forms/policies from **APD** (Authorization Policy Database), authorizes
requests, and orchestrates execution.

It speaks **REST** and is backed by a **PostgreSQL** database (`p3dx_governance`).

> Drop-in Go replacement for the original Node.js implementation: identical REST
> endpoints, JSON shapes, status codes, and database schema. Go-only; Node sources
> removed. Contract model unified: single endpoint routes to FL, TEE, or SMPC
> orchestration based on technique field.

---

## What the Governance Layer is used for

- **Contract intake** — receives contracts with technique (FL/TEE/SMPC) and datasets
- **Form/Policy lookup** — fetches forms (FL pathway) or policies (General pathway) from APD
- **Authorization** — validates user tokens and authorizes against dataset policies
- **Contract storage** — persists contracts for audit trail
- **Orchestration routing** — routes to appropriate executor (FL receiver, TEE, SMPC network)
- **Notifications** — manages participation consent loop (FL pathway)

---

## Where it sits (architecture)

```
        ┌─────────────┐        ┌────────────────┐        ┌──────────┐
        │  Clients    │        │     APD        │        │ Keycloak │
        │ (FL Owner,  │        │  (Forms,       │        │   (Auth) │
        │  SMPC Node) │        │   Policies)    │        │          │
        └──────┬──────┘        └────────┬───────┘        └────┬─────┘
               │                        │                     │
               │  POST /contract        │                     │
               │  (technique, datasets) │                     │
               └─────────┬──────────────┴─────────────────────┘
                         │
                         ▼
        ┌─────────────────────────────────────────────┐
        │   Governance Layer (this repo)              │
        │   REST :8083 (contracts, notifications)     │
        │   - Routes by technique (FL/TEE/SMPC)       │
        │   - Fetches forms/policies from APD         │
        │   - Authorizes against policies             │
        └────┬──────────────┬──────────────┬──────────┘
             │              │              │
             ▼              ▼              ▼
        PostgreSQL     FL Receivers   TEE/SMPC
        (contracts,    (orchest.      Executors
        notif.)        :8090/:8080)   (outside)
```

---

## Contract Processing Flow

**Single endpoint: `POST /contract`**

Contract includes: `technique` ("FL" | "TEE" | "SMPC"), `datasets` ([{id, name}, ...])

**FL Pathway** (technique = "FL")
1. Extract datasets from contract
2. Fetch forms from APD for each dataset
3. Store contract in DB (pathway="FL")
4. Return 202 Accepted — FL orchestration via separate flow

**General Pathway** (technique = "TEE" or "SMPC")
1. Extract datasets from contract
2. Fetch policies from APD for each dataset
3. Authorize user against each dataset's policy
4. Encrypt contract to disk
5. Store contract in DB (pathway="GENERAL")
6. Sign with orchestrator key
7. Deploy to TEE/SMPC executor
8. Return contract ID + orchestrator signature

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
| `httpapi/server.go` | Wires the router (chi), CORS, JSON helpers, and mounts every route under both `/api/v1` and `/governance`. Holds the `Server` (config + DB + Keycloak). |
| `httpapi/general_contract.go` | `POST /contract` — unified contract endpoint for FL/TEE/SMPC. Routes by technique, fetches forms/policies from APD, authorizes, and orchestrates accordingly. |
| `httpapi/fl_notifications.go` | Request handlers for notifications (create / list / read / **respond** / **by-sender**). |
| `httpapi/fl_forms.go` | Request handlers for mock provider directory and provider messages. |
| `httpapi/model.go`, `httpapi/inspect_model.py` | `GET /final-models`, `/final-model/download`, `/final-model/summary` — locates and summarizes flo_server's final model checkpoints via embedded `.pt` reader. |

### `internal/services` — Business logic
| File | Purpose |
|------|---------|
| `services/apd.go` | APD integration: `FetchDatasetForm()` for FL, `AuthorizeContractAgainstAPD()` for General pathway, policy evaluation, private dataset email notifications. |
| `services/token.go` | Keycloak token validation via JWKS, claim extraction. |
| `services/crypto.go` | RSA signature verification and signing operations. |
| `services/storage.go` | `SecureStore()` — AES-GCM encryption of contracts to disk. |
| `services/enclave.go` | `DeployEnclave()` — HTTP POST of signed contracts to TEE/SMPC executor. |

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
| **Server** |
| `PORT` | REST API port | `8083` |
| `NODE_ENV` | Environment label | `development` |
| `CORS_ORIGINS` | Comma-separated allowed origins | — |
| **Database** |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | PostgreSQL connection | `localhost` / `5432` / `p3dx_governance` / `postgres` / `postgres` |
| **Authentication** |
| `KEYCLOAK_BASE_URL` / `KEYCLOAK_REALM` / `KEYCLOAK_CLIENT_ID` / `KEYCLOAK_CLIENT_SECRET` | Keycloak service-account auth | — |
| `PUSH_AUTH_TOKEN` | Legacy `X-Auth-Token` fallback when Keycloak is unset | — |
| **APD (Authorization Policy Database)** |
| `APD_BASE_URL` | APD service URL for fetching forms/policies | `http://localhost:8091` |
| `APD_POLICY_PATH_TEMPLATE` | Custom template for policy paths (supports `{item_id}`, `{policy_id}`) | — |
| `APD_FORMS_TOKEN` | `X-Forms-Push-Token` sent when calling APD's forms endpoints (must match APD's `FORMS_PUSH_TOKEN`) | — |
| **General Pathway (TEE/SMPC)** |
| `ORCH_PRIVATE_KEY` | Path to orchestrator private key file | — |
| `STORE_KEY` | Encryption key for secure contract storage | — |
| `STORE_PATH` | Directory for encrypted contracts | — |
| **Private Dataset Notifications** |
| `SMTP_HOST` | SMTP server hostname | — |
| `SMTP_PORT` | SMTP server port | `587` |
| `SENDER_EMAIL` | Email address for notifications | — |
| `SENDER_PASSWORD` | SMTP password (app password for Gmail) | — |

---

## API

All REST routes are mounted under **both** `/api/v1` and `/governance` (CORS enabled, flexible origins).

### Contract Endpoint (Unified)

**Single endpoint for all techniques:**

| Method | Path | Purpose | Input |
|--------|------|---------|-------|
| `POST` | `/contract` | Submit contract with technique (FL/TEE/SMPC) and datasets | `{access_token, contract, signature}` |
| `GET` | `/contract/{sessionId}` | Retrieve stored contract | — |

**Contract Request Format:**
```json
{
  "access_token": "...",
  "contract": {
    "technique": "FL|TEE|SMPC",
    "datasets": [
      { "id": "dataset-1", "name": "...", "provider_id": "..." },
      { "id": "dataset-2", "name": "...", "provider_id": "..." }
    ],
    ...
  },
  "signature": "hex-encoded-user-signature"
}
```

**Processing:**
- **FL pathway** (technique="FL"): Fetches forms from APD, stores contract (202 Accepted)
- **General pathway** (technique="TEE"/"SMPC"): Fetches policies from APD, authorizes, encrypts, signs, deploys (200 OK)

### Notifications & Consent (FL-Specific)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/notifications` | Create participation-request notifications |
| `GET` | `/notifications/{key}` | Fetch notifications for a user |
| `GET` | `/notifications/by-sender/{key}` | Fetch notifications sent by a user |
| `PATCH` | `/notifications/{key}/read` | Mark notification as read |
| `POST` | `/notifications/{key}/respond` | Provider responds (accepted/declined + reason) |

### Data Providers & Messages

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/data-providers` | List registered data providers |
| `POST` | `/send-provider-message` | Send message to a data provider |

### Final Models

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/final-models` | List final (highest-round) models for all sessions |
| `GET` | `/final-model/download` | Download model checkpoint file |
| `GET` | `/final-model/summary` | Get model architecture summary |

#### FL Orchestration (FL-Specific)

| Method | Path | Purpose | Pathway |
|--------|------|---------|---------|
| `POST` | `/distribute-config` | Distribute client_config.yaml to providers via SCP | FL |
| `POST` | `/provision-env` | Provision Python virtual environments on selected providers | FL |
| `POST` | `/push-config` | HTTP-push rendered client_config.yaml to providers | FL |
| `POST` | `/start-fl-session` | Complete FL orchestration in one call: owner env → server → provider envs → config → clients → session | FL |
| `GET` | `/client-config/by-submission/:id` | Retrieve rendered client config for a form submission | FL |
| `GET` | `/client-config/:username` | Retrieve rendered client config for a provider (pulled during setup) | FL |

### Contract Pathway Details

**FL Pathway Flow:**
1. Create form submission via aaa (owner config + selected providers)
2. aaa pushes form to governance layer
3. Build initial contract (participation request, `finalize=false`)
4. Send notifications to providers
5. Wait for provider responses
6. Build final contract (confirmed roster, `finalize=true`)
7. Orchestrate: distribute config → provision envs → push config → start clients → start session
8. Retrieve final models and report

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


# jobs -l
# pkill -f "src/server.js"
# ss -ltnp | grep 3001

# apd ==> go run ./cmd/server/main.go

Or build a binary:

```bash
go build -o gov-layer ./cmd/server
./gov-layer
```

The repo's `../start.sh` launches the whole P3DX stack and starts this service
with `go run ./cmd/server`.
