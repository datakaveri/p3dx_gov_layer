// Command server is the Governance Layer entry point. It starts both:
//  1. the REST API (port 8083 by default) for frontend/AAA communication, and
//  2. the gRPC server (port 50052) for backend-to-backend communication,
//
// backed by PostgreSQL. It is a drop-in replacement for the original Node
// service (src/server.js) — same ports, env vars, database and behaviour.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/grpcsrv"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/httpapi"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/keycloak"
)

func main() {
	// Load .env with override semantics before reading any config — must be first.
	config.LoadEnv()
	cfg := config.Load()

	ctx := context.Background()

	// Initialize the database (auto-create + migrate), matching initializeApp().
	database, err := db.Initialize(ctx, cfg)
	if err != nil {
		log.Fatalf("[ERROR] Failed to start server: %v", err)
	}
	defer database.Close()

	kc := keycloak.New(cfg)
	api := httpapi.New(cfg, database, kc)

	// REST (HTTP) server.
	restServer := &http.Server{
		Addr:    ":" + cfg.RESTPort,
		Handler: api.Handler(),
	}

	// gRPC server.
	grpcServer, err := grpcsrv.Start(database, cfg.GRPCPort)
	if err != nil {
		log.Fatalf("[ERROR] Failed to start gRPC server: %v", err)
	}

	go func() {
		log.Printf("[REST] Governance Layer server running on port %s", cfg.RESTPort)
		log.Printf("[REST] Environment: %s", orDefault(cfg.NodeEnv, "development"))
		log.Printf("[REST] CORS Origins: %s", orDefault(cfg.CORSRaw, "Not configured"))
		log.Printf("[REST] Database: PostgreSQL")
		if err := restServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[ERROR] REST server failed: %v", err)
		}
	}()

	log.Printf("[INFO] Both servers started successfully")
	log.Printf("[INFO] REST API: http://localhost:%s", cfg.RESTPort)
	log.Printf("[INFO] gRPC: localhost:%s", cfg.GRPCPort)

	// Graceful shutdown on SIGINT/SIGTERM, mirroring the SIGTERM handler in server.js.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("[INFO] Signal received: closing HTTP and gRPC servers")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := restServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERROR] Error shutting down HTTP server: %v", err)
	} else {
		log.Println("[INFO] HTTP server closed")
	}
	grpcServer.GracefulStop()
	log.Println("[INFO] gRPC server shut down")
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
