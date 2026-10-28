// Command migrate applies the Governance Layer's pending database migrations
// (internal/repository/postgres/migrations) and exits. Run it once per deploy, before starting
// the server replicas, and set DB_AUTO_MIGRATE=false on the servers. It reads
// the same DB_* env vars / .env as the server.
package main

import (
	"context"
	"log"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

func main() {
	config.LoadEnv()
	cfg := config.Load()

	if err := postgres.Migrate(context.Background(), cfg); err != nil {
		log.Fatalf("[ERROR] Migration failed: %v", err)
	}
}
