package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vmp-backend/internal/httpapi"
	"vmp-backend/internal/platform"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	databaseURL := env("DATABASE_URL", "postgres://vmlease:vmlease-dev@localhost:5432/vmlease?sslmode=disable")
	service, err := platform.New(ctx, databaseURL)
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer service.DB.Close()
	go platform.StartReconciler(ctx, service)
	api := &httpapi.API{Service: service, BootstrapToken: env("AGENT_BOOTSTRAP_TOKEN", "dev-bootstrap-token"), AgentToken: env("AGENT_RUNTIME_TOKEN", "dev-agent-token")}
	server := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	slog.Info("control plane listening", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
