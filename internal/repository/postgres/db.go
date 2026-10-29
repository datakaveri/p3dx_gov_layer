// Package db is the PostgreSQL data layer for the Governance Layer. It mirrors
// src/services/database.service.js: same database, same schema, same migrations
// and the same query semantics, so the Go service is a drop-in replacement that
// reads and writes the existing p3dx_governance database unchanged. Its schema
// is defined by the numbered files in migrations/ (see migrate.go).
package postgres

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

// Initialize connects to the target database and makes sure its schema is
// current. Schema changes are numbered files in migrations/ (see migrate.go),
// normally applied once per deploy by the migrate job (cmd/migrate). With
// DB_AUTO_MIGRATE=true (the default) the server applies any pending ones
// itself, under an advisory lock so replicas take turns; with
// DB_AUTO_MIGRATE=false it only checks and refuses to start if one is missing.
func Initialize(ctx context.Context, cfg *config.Config) (*DB, error) {
	if cfg.DBAutoMigrate {
		if err := ensureDatabase(ctx, cfg); err != nil {
			return nil, err
		}
	}

	poolCfg, err := pgxpool.ParseConfig(dsn(cfg, cfg.DBName))
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
	log.Printf("[DATABASE] Connected to database '%s'", cfg.DBName)

	if cfg.DBAutoMigrate {
		err = applyMigrations(ctx, pool)
	} else {
		err = checkMigrations(ctx, pool)
	}
	if err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{Pool: pool}, nil
}

// Close releases the pool.
func (d *DB) Close() { d.Pool.Close() }

// Ping checks that Postgres answers; GET /ready uses it.
func (d *DB) Ping(ctx context.Context) error { return d.Pool.Ping(ctx) }

// ensureDatabase connects to the default "postgres" database and creates the
// target database if it does not exist yet.
func ensureDatabase(ctx context.Context, cfg *config.Config) error {
	dbName := cfg.DBName

	defaultPool, err := pgxpool.New(ctx, dsn(cfg, "postgres"))
	if err != nil {
		return fmt.Errorf("connect to default database: %w", err)
	}
	defer defaultPool.Close()
	if err := defaultPool.Ping(ctx); err != nil {
		return fmt.Errorf("ping default database: %w", err)
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
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
		log.Printf("[DATABASE] Database '%s' created successfully", dbName)
	default:
		return fmt.Errorf("check database existence: %w", err)
	}
	return nil
}
