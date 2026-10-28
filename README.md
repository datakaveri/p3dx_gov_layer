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

### Package layout

Each kind of code has one home. Dependencies point inward:
`transport → application → domain`; `repository` and `integration` are used by
the outer layers, and `domain` imports nothing else from this module.

| Folder | Kind of code | Contents |
|--------|--------------|----------|
| `internal/domain/contract` | Rules | The standard contract JSON shape (`Contract`, parties, signatures) and its validation. |
| `internal/domain/workload` | Rules | Known TEE workloads (`KnownWorkloads`) and the policy check `PolicyAllowsWorkload`. |
| `internal/application/contractgen` | Steps | `BuildGeneratedContract` — assembles a contract from datasets, infra and policies. |
| `internal/repository/postgres` | Database | pgx connection pool, every table's queries, and numbered migrations (`migrations/*.sql`, run by `cmd/migrate`). |
| `internal/integration/apd` | Other services | p3dx-apd: policy fetch/evaluation, provider forms, consumer grants. |
| `internal/integration/catalogue` | Other services | Provider catalogue and DX catalogue lookups. |
| `internal/integration/keycloak` | Other services | Service-account token client (`keycloak.go`) and access-token validation via JWKS (`token.go`). |
| `internal/integration/tee` | Other services | Enclave deploy, Azure VM control, MAA attestation, and the APD-facing `TEEContract`. |
| `internal/integration/userdir` | Other services | User directory and Flotilla credential grants. |
| `internal/platform/govcrypto` | Shared plumbing | Governance key and CA, contract-hash signatures, RSA helpers, AES-GCM `SecureStore`. |
| `internal/transport/httpapi` | APIs | chi router (`server.go`), every HTTP handler, OpenAPI docs, `inspect_model.py`. |
| `internal/config` | Shared plumbing | Environment / `.env` config loading. |

There is no `internal/worker` yet: nothing runs in the background outside a
request. Add it when the first scheduled or queue-driven job appears.

### Other
| Path | Purpose |
|------|---------|
| `.env.example` | Template for the runtime config (`.env` is gitignored — it holds secrets). |
| `go.mod` / `go.sum` | Go module + dependency checksums. |

---

## Data model (tables, from `internal/repository/postgres/migrations`)

Schema changes go in a new numbered file, `internal/repository/postgres/migrations/NNNN_description.sql`.
Never edit a file that has already been applied. Each file runs once, in a
transaction, and is recorded in `schema_migrations` (version, name, applied_at).
Deploy order: run `gov-layer-migrate` once, then start the servers with
`DB_AUTO_MIGRATE=false`. Single-instance/local runs can keep the default
(`true`), which applies pending files at startup under a Postgres advisory lock.

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
| `DB_AUTO_MIGRATE` | Apply pending migrations at server startup. Set `false` when the migrate job runs them (multiple replicas) | `true` |
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

Users read and answer their own notifications under `/me/notifications` (identity from the token). Answering a participation request with `accepted` also signs that provider's party on the session's contract (best-effort, via the notification's `submission_id` payload field).

### Final Models

| Method | Path | Purpose |
|--------|------|---------|
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
1. Build contract externally (arbitrary `compute_choice`)
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


jobs -l
pkill -f "src/server.js"
ss -ltnp | grep 3001

# apd ==> go run ./cmd/server/main.go

Or build a binary:

```bash
go build -o gov-layer ./cmd/server
./gov-layer
```

The repo's `../start.sh` launches the whole P3DX stack and starts this service
with `go run ./cmd/server`.
