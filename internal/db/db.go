// Package db is the PostgreSQL data layer for the Governance Layer. It mirrors
// src/services/database.service.js: same database, same schema, same migrations
// and the same query semantics, so the Go service is a drop-in replacement that
// reads and writes the existing p3dx_governance database unchanged.
package db

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
)

// DB wraps the connection pool to the target (p3dx_governance) database.
type DB struct {
	Pool *pgxpool.Pool
}

// dsn builds a libpq key/value DSN for the given database name. SSL is disabled
// to match node-postgres' default (no TLS) for the local Postgres deployment.
func dsn(cfg *config.Config, dbName string) string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, dbName)
}

// Initialize connects to PostgreSQL, auto-creates the target database if it does
// not exist, then ensures every table/column/index exists. It reproduces
// initializeDatabase() exactly (create-if-missing + idempotent migrations) so
// data persists across restarts and an upgraded older database is patched.
func Initialize(ctx context.Context, cfg *config.Config) (*DB, error) {
	dbName := cfg.DBName

	// 1) Connect to the default "postgres" database to check/create the target.
	defaultPool, err := pgxpool.New(ctx, dsn(cfg, "postgres"))
	if err != nil {
		return nil, fmt.Errorf("connect to default database: %w", err)
	}
	if err := defaultPool.Ping(ctx); err != nil {
		defaultPool.Close()
		return nil, fmt.Errorf("ping default database: %w", err)
	}
	log.Println("[DATABASE] Connected to PostgreSQL (default database)")

	var exists int
	row := defaultPool.QueryRow(ctx, `SELECT 1 FROM pg_database WHERE datname = $1`, dbName)
	switch err := row.Scan(&exists); err {
	case nil:
		log.Printf("[DATABASE] Database '%s' already exists", dbName)
	case pgx.ErrNoRows:
		log.Printf("[DATABASE] Database '%s' does not exist, creating...", dbName)
		// CREATE DATABASE cannot run in a transaction; pgx Exec runs it standalone.
		if _, err := defaultPool.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", dbName)); err != nil {
			defaultPool.Close()
			return nil, fmt.Errorf("create database %q: %w", dbName, err)
		}
		log.Printf("[DATABASE] Database '%s' created successfully", dbName)
	default:
		defaultPool.Close()
		return nil, fmt.Errorf("check database existence: %w", err)
	}
	defaultPool.Close()

	// 2) Connect to the target database.
	poolCfg, err := pgxpool.ParseConfig(dsn(cfg, dbName))
	if err != nil {
		return nil, fmt.Errorf("parse target db config: %w", err)
	}
	poolCfg.MaxConns = 25
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connect to target database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping target database: %w", err)
	}
	log.Printf("[DATABASE] Connected to database '%s'", dbName)

	d := &DB{Pool: pool}
	if err := d.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return d, nil
}

// Close releases the pool.
func (d *DB) Close() { d.Pool.Close() }

// migrate runs every CREATE TABLE / ALTER / index from database.service.js. All
// statements are idempotent (IF NOT EXISTS), matching the Node startup path.
func (d *DB) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS notifications (
			id TEXT PRIMARY KEY,
			recipient_id TEXT NOT NULL,
			recipient_username TEXT NOT NULL,
			sender_username TEXT NOT NULL,
			message TEXT NOT NULL,
			payload JSONB,
			read BOOLEAN DEFAULT false,
			read_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS notifications_recipient_idx ON notifications(recipient_username)`,
		// Participation-consent loop: a provider answers a "still willing?" request
		// with accepted/declined plus an optional free-text reason for the owner.
		`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS response TEXT`,
		`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS response_message TEXT`,
		`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS responded_at TIMESTAMP`,
		`CREATE INDEX IF NOT EXISTS notifications_sender_idx ON notifications(sender_username)`,
		`CREATE TABLE IF NOT EXISTS session_reports (
			id TEXT PRIMARY KEY,
			submission_id TEXT UNIQUE NOT NULL,
			form_id TEXT,
			output_owner_id TEXT,
			report JSONB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		// Contracts assembled when the output owner selects providers. One row
		// per contract build: BuildContract mints a fresh project_id/contract_id
		// on every call, so a session (session_id = form submission id)
		// accumulates a new row for its initial (participation-request)
		// contract, its final (roster) contract, and any "Start Again" restart -
		// none of them reuse a previous row. pathway distinguishes FL contracts
		// (with forms flow) from GENERAL contracts (with policy checks).
		`CREATE TABLE IF NOT EXISTS contracts (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			output_owner_id TEXT,
			finalized BOOLEAN DEFAULT false,
			pathway TEXT DEFAULT 'FL',
			contract JSONB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`ALTER TABLE contracts ADD COLUMN IF NOT EXISTS pathway TEXT DEFAULT 'FL'`,
		// One row per (role, participant_name): the IP of each participant VM
		// that terraform/participant-vm registers after creating it. "user" rows
		// are the output-owner(s); GetOutputOwnerVM returns the most recently
		// updated one. See internal/db/vm_registry.go.
		`CREATE TABLE IF NOT EXISTS vm_registry (
			role TEXT NOT NULL,
			participant_name TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (role, participant_name)
		)`,
		// One row per contract build, recording the project_id assigned in
		// contracts (see BuildContract) alongside who is participating: the
		// output owner and the data-provider parties on that specific contract.
		// Populated for every contract - draft, final, and "Start Again"
		// restarts alike - via UpsertProject in projects.go, always as a new
		// row since project_id is always freshly minted.
		`CREATE TABLE IF NOT EXISTS projects (
			project_id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			output_owner_username TEXT,
			data_provider_usernames JSONB NOT NULL DEFAULT '[]',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		// "Start Again" (restart-fl-session) mints a new project_id/contract_id
		// for the same session rather than overwriting the previous project, so
		// a session can now have several contracts/projects (its restart
		// history). Drop the old one-row-per-session uniqueness and instead
		// enforce uniqueness per project_id, which is what the upserts below key
		// on now.
		`ALTER TABLE contracts DROP CONSTRAINT IF EXISTS contracts_session_id_key`,
		`ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_session_id_key`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'contracts_project_id_key'
			) THEN
				ALTER TABLE contracts ADD CONSTRAINT contracts_project_id_key UNIQUE (project_id);
			END IF;
		END $$`,
		`CREATE INDEX IF NOT EXISTS contracts_session_id_idx ON contracts(session_id)`,
		`CREATE INDEX IF NOT EXISTS projects_session_id_idx ON projects(session_id)`,
		// StoreGeneratedContract (preview contracts, keyed by a synthetic
		// "preview:<consumer>:<dataset>:<technique>" session_id) still needs
		// regenerating the same selection to overwrite rather than accumulate -
		// scope that uniqueness to just those rows so it doesn't reintroduce the
		// one-row-per-real-session limit dropped above.
		`CREATE UNIQUE INDEX IF NOT EXISTS contracts_preview_session_id_key ON contracts(session_id) WHERE session_id LIKE 'preview:%'`,
	}
	for _, s := range stmts {
		if _, err := d.Pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	log.Println("[DATABASE] Table notifications ready")
	log.Println("[DATABASE] Table session_reports ready")
	log.Println("[DATABASE] Table contracts ready")
	log.Println("[DATABASE] Table vm_registry ready")
	log.Println("[DATABASE] Database initialization complete")
	return nil
}
