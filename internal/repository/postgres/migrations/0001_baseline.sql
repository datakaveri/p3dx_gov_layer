-- Baseline: the schema the service used to create on every startup (the old
-- db.migrate in internal/db/db.go). Every statement is idempotent, so it is a
-- no-op on a database that already has these tables and is simply recorded as
-- applied in schema_migrations.

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  recipient_id TEXT NOT NULL,
  recipient_username TEXT NOT NULL,
  sender_username TEXT NOT NULL,
  message TEXT NOT NULL,
  payload JSONB,
  read BOOLEAN DEFAULT false,
  read_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS notifications_recipient_idx ON notifications(recipient_username);
-- Participation-consent loop: a provider answers a "still willing?" request
-- with accepted/declined plus an optional free-text reason for the owner.
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS response TEXT;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS response_message TEXT;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS responded_at TIMESTAMP;
CREATE INDEX IF NOT EXISTS notifications_sender_idx ON notifications(sender_username);
CREATE TABLE IF NOT EXISTS session_reports (
  id TEXT PRIMARY KEY,
  submission_id TEXT UNIQUE NOT NULL,
  form_id TEXT,
  output_owner_id TEXT,
  report JSONB NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Contracts assembled when the output owner selects providers. One row
-- per contract build: BuildContract mints a fresh project_id/contract_id
-- on every call, so a session (session_id = form submission id)
-- accumulates a new row for its initial (participation-request)
-- contract, its final (roster) contract, and any "Start Again" restart -
-- none of them reuse a previous row. pathway distinguishes FL contracts
-- (with forms flow) from GENERAL contracts (with policy checks).
CREATE TABLE IF NOT EXISTS contracts (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  output_owner_id TEXT,
  finalized BOOLEAN DEFAULT false,
  pathway TEXT DEFAULT 'FL',
  contract JSONB NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE contracts ADD COLUMN IF NOT EXISTS pathway TEXT DEFAULT 'FL';
-- One row per (role, participant_name): the IP of each participant VM
-- that terraform/participant-vm registers after creating it. "user" rows
-- are the output-owner(s); GetOutputOwnerVM returns the most recently
-- updated one. See internal/db/vm_registry.go.
CREATE TABLE IF NOT EXISTS vm_registry (
  role TEXT NOT NULL,
  participant_name TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (role, participant_name)
);

-- One row per contract build, recording the project_id assigned in
-- contracts (see BuildContract) alongside who is participating: the
-- output owner and the data-provider parties on that specific contract.
-- Populated for every contract - draft, final, and "Start Again"
-- restarts alike - via UpsertProject in projects.go, always as a new
-- row since project_id is always freshly minted.
CREATE TABLE IF NOT EXISTS projects (
  project_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  output_owner_username TEXT,
  data_provider_usernames JSONB NOT NULL DEFAULT '[]',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- "Start Again" (restart-fl-session) mints a new project_id/contract_id
-- for the same session rather than overwriting the previous project, so
-- a session can now have several contracts/projects (its restart
-- history). Drop the old one-row-per-session uniqueness and instead
-- enforce uniqueness per project_id, which is what the upserts below key
-- on now.
ALTER TABLE contracts DROP CONSTRAINT IF EXISTS contracts_session_id_key;
ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_session_id_key;
DO $$
BEGIN
IF NOT EXISTS (
	SELECT 1 FROM pg_constraint WHERE conname = 'contracts_project_id_key'
) THEN
	ALTER TABLE contracts ADD CONSTRAINT contracts_project_id_key UNIQUE (project_id);
END IF;
END $$;

CREATE INDEX IF NOT EXISTS contracts_session_id_idx ON contracts(session_id);
CREATE INDEX IF NOT EXISTS projects_session_id_idx ON projects(session_id);
-- StoreGeneratedContract (preview contracts, keyed by a synthetic
-- "preview:<consumer>:<dataset>:<technique>" session_id) still needs
-- regenerating the same selection to overwrite rather than accumulate -
-- scope that uniqueness to just those rows so it doesn't reintroduce the
-- one-row-per-real-session limit dropped above.
CREATE UNIQUE INDEX IF NOT EXISTS contracts_preview_session_id_key ON contracts(session_id) WHERE session_id LIKE 'preview:%';
-- Every contract has its own job_id (minted in BuildContract /
-- BuildGeneratedContract before hashing, and in contract.JobID). Rows
-- from before this column existed are backfilled with a fresh id in the
-- column only - their stored JSON is left alone, since contract_signing
-- recomputes the hash from it and adding job_id would break existing
-- signatures.
ALTER TABLE contracts ADD COLUMN IF NOT EXISTS job_id TEXT;
UPDATE contracts
SET job_id = 'job-' || (FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000))::bigint || '-' || substr(md5(random()::text || id), 1, 9)
WHERE job_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS contracts_job_id_key ON contracts(job_id);
-- Audit trail for job approvals (audit.go): one row per check of one
-- provider + item (dataset or infra) on a contract's job_id - whether
-- the provider holds the data-provider / infra-provider role and has
-- that item in their APD catalogue. Append-only; the latest row per
-- (job_id, type, provider_id, item) is the current status.
CREATE TABLE IF NOT EXISTS audit (
  id BIGSERIAL PRIMARY KEY,
  job_id TEXT NOT NULL,
  type TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  item TEXT NOT NULL,
  status TEXT NOT NULL,
  has_role BOOLEAN NOT NULL DEFAULT false,
  in_catalogue BOOLEAN NOT NULL DEFAULT false,
  reason TEXT,
  checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS audit_job_key_idx ON audit(job_id, type, provider_id, item, checked_at);
-- When a contract's sign requests went out. Contracts that need job
-- approval hold them until every approval is accepted, then send them
-- exactly once (MarkSignRequestsSent claims this atomically).
ALTER TABLE contracts ADD COLUMN IF NOT EXISTS sign_requests_sent_at TIMESTAMP;
-- Job lifecycle after approval (audit.go): when a job's contract became
-- final (every data and infra provider approved and signed, plus the
-- governance signature) and when its consumer enabled the TEE run.
-- Kept in columns, not the contract JSON, so the signed hash is
-- unaffected.
ALTER TABLE contracts ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMP;
ALTER TABLE contracts ADD COLUMN IF NOT EXISTS tee_enabled_at TIMESTAMP;
-- What happened to each contract, in order (contract_events.go) —
-- generated, sign requested, signed, edited, run started / refused /
-- failed — for the data provider's live Audit page. Append-only, so
-- it keeps the history even after a draft row is regenerated.
CREATE TABLE IF NOT EXISTS contract_events (
  id BIGSERIAL PRIMARY KEY,
  contract_id TEXT NOT NULL,
  job_id TEXT NOT NULL DEFAULT '',
  event TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS contract_events_job_idx ON contract_events(job_id);
CREATE INDEX IF NOT EXISTS contract_events_contract_idx ON contract_events(contract_id);
-- A job's final contract (final_contracts.go): the governance-signed
-- contract, stored once at GET /job/{jobId}/status after every
-- approval, the contract hash and every signature verified. Its own
-- table so it stays as created while the contracts row moves on.
CREATE TABLE IF NOT EXISTS final_contracts (
  job_id TEXT PRIMARY KEY,
  contract_id TEXT NOT NULL,
  contract_hash TEXT NOT NULL,
  contract JSONB NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One RSA public key per provider user (data-provider / infra-provider),
-- generated in their browser and registered via PUT /provider-keys; the
-- contract-signing flow verifies their signatures against it. See
-- internal/db/public_keys.go.
CREATE TABLE IF NOT EXISTS provider_public_keys (
  username TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL,
  public_key_pem TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Who takes part in each job (job_participants.go): one row per
-- consumer, and per data / infra provider and the dataset / infra they
-- bring, with that user's status on the job. Written as the job moves
-- (generate-contract, approvals, signing, final, TEE) so
-- GET /jobs/user/{userId} can list a user's contracts.
CREATE TABLE IF NOT EXISTS job_participants (
  job_id TEXT NOT NULL,
  contract_id TEXT NOT NULL,
  technique TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL,
  participant_id TEXT NOT NULL,
  user_id TEXT NOT NULL DEFAULT '',
  username TEXT NOT NULL DEFAULT '',
  item_id TEXT NOT NULL DEFAULT '',
  item_name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (job_id, role, participant_id, item_id)
);

CREATE INDEX IF NOT EXISTS job_participants_participant_idx ON job_participants(lower(participant_id));
CREATE INDEX IF NOT EXISTS job_participants_user_idx ON job_participants(lower(user_id));
-- One row per Flotilla gateway TLS certificate issued by the
-- governance CA (POST /gateway-certs): which FL contract it was issued
-- for, to whom (requested_by = the orchestrator token's azp), and when
-- it expires (the contract's valid_until). See internal/db/gateway_certs.go.
CREATE TABLE IF NOT EXISTS gateway_certs (
  serial TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  project_id TEXT,
  contract_id TEXT,
  job_id TEXT,
  server_ip TEXT,
  fingerprint_sha256 TEXT NOT NULL,
  not_after TIMESTAMP NOT NULL,
  requested_by TEXT,
  issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS gateway_certs_submission_id_idx ON gateway_certs(submission_id);
-- FL participation negotiation: a provider who declines their second
-- (or later) participation request for a session is removed from that
-- session for good. See internal/db/fl_notifications.go.
CREATE TABLE IF NOT EXISTS fl_session_removed_providers (
  submission_id TEXT NOT NULL,
  username TEXT NOT NULL,
  reason TEXT,
  removed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (submission_id, username)
);

-- Flotilla FL client-VM credentials: one row per offline token issued
-- to a data provider's FL VM. Only a fingerprint of the token is kept,
-- never the token or the password. See internal/db/fl_vm_credentials.go.
CREATE TABLE IF NOT EXISTS fl_vm_credentials (
  credential_id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  contract_id TEXT,
  username TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL,
  state_reason TEXT,
  token_fingerprint TEXT NOT NULL,
  issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  state_changed_at TIMESTAMP,
  rotated_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS fl_vm_credentials_submission_id_idx ON fl_vm_credentials(submission_id);
