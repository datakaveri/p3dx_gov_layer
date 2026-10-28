package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
)

// Schema changes live in numbered files under migrations/ (0001_baseline.sql,
// 0002_….sql, …). Each file runs once, in its own transaction, and is then
// recorded in schema_migrations, which is the history of what changed and
// when. Never edit a file that has been applied anywhere; add a new one.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrationLockID is the pg_advisory_lock key held while migrating, so two
// runners started together (several replicas, or the migrate job plus a
// replica) take turns instead of changing the tables at the same time.
const migrationLockID int64 = 0x70336478_676f76 // "p3dx" "gov"

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	seen := map[int]string{}
	for _, e := range entries {
		name := e.Name()
		num, _, ok := strings.Cut(name, "_")
		version, err := strconv.Atoi(num)
		if !ok || err != nil || !strings.HasSuffix(name, ".sql") {
			return nil, fmt.Errorf("migration %q: name must look like 0001_description.sql", name)
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", prev, name, version)
		}
		seen[version] = name
		body, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: version, name: name, sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	return ms, nil
}

const createMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)`

func appliedVersions(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (map[int]bool, error) {
	rows, err := q.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	versions, err := pgx.CollectRows(rows, pgx.RowTo[int])
	if err != nil {
		return nil, err
	}
	applied := make(map[int]bool, len(versions))
	for _, v := range versions {
		applied[v] = true
	}
	return applied, nil
}

// Migrate creates the target database if it is missing and applies every
// pending migration. It is what cmd/migrate runs as the one-off deploy job.
func Migrate(ctx context.Context, cfg *config.Config) error {
	if err := ensureDatabase(ctx, cfg); err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, dsn(cfg, cfg.DBName))
	if err != nil {
		return fmt.Errorf("connect to target database: %w", err)
	}
	defer pool.Close()
	return applyMigrations(ctx, pool)
}

func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}

	// Advisory locks belong to a session, so hold one connection throughout.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("migrate: lock: %w", err)
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID)

	if _, err := conn.Exec(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("migrate: create schema_migrations: %w", err)
	}
	// Read only after taking the lock: whoever held it before may have just
	// applied some of these.
	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		return fmt.Errorf("migrate: read schema_migrations: %w", err)
	}

	n := 0
	for _, m := range ms {
		if applied[m.version] {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			// No arguments, so pgx sends the whole file as one simple-protocol
			// query - multiple statements and DO $$ … $$ blocks work as-is.
			if _, err := tx.Exec(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name)
			return err
		})
		if err != nil {
			return fmt.Errorf("migrate %s: %w", m.name, err)
		}
		log.Printf("[DATABASE] Applied migration %s", m.name)
		n++
	}
	log.Printf("[DATABASE] Schema up to date (%d migration(s) applied now, %d total)", n, len(ms))
	return nil
}

// checkMigrations fails when the database is missing a migration this build
// expects, so a server started before the migrate job ran says so clearly
// instead of failing later on a missing table or column.
func checkMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		return fmt.Errorf("read schema_migrations (has the migrate job run?): %w", err)
	}
	var pending []string
	for _, m := range ms {
		if !applied[m.version] {
			pending = append(pending, m.name)
		}
	}
	if len(pending) > 0 {
		return fmt.Errorf("database schema is behind this build, pending migrations: %s - run the migrate job (gov-layer-migrate) first", strings.Join(pending, ", "))
	}
	log.Printf("[DATABASE] Schema up to date (%d migrations)", len(ms))
	return nil
}
