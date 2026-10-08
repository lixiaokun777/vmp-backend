package main

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vmp-backend/internal/httpapi"
	"vmp-backend/internal/platform"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	databaseURL := env("DATABASE_URL", "postgres://vmlease:vmlease-dev@localhost:5432/vmlease?sslmode=disable")
	trustedProxies, err := httpapi.ParseTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		slog.Error("invalid trusted proxy configuration", "error", err)
		os.Exit(1)
	}
	service, err := platform.New(ctx, databaseURL)
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer service.DB.Close()
	go platform.StartReconciler(ctx, service)
	api := &httpapi.API{
		Service:               service,
		BootstrapToken:        env("AGENT_BOOTSTRAP_TOKEN", "dev-bootstrap-token"),
		AgentToken:            env("AGENT_RUNTIME_TOKEN", "dev-agent-token"),
		SessionTTL:            time.Duration(envInt("SESSION_TTL_HOURS", 12)) * time.Hour,
		SessionSecure:         envBool("SESSION_COOKIE_SECURE", false),
		TrustedProxies:        trustedProxies,
		SettingsEncryptionKey: settingsEncryptionKey(os.Getenv("SETTINGS_ENCRYPTION_KEY")),
		ConsoleSigningKey:     consoleSigningKey(os.Getenv("CONSOLE_SIGNING_KEY")),
		LDAP: httpapi.LDAPConfig{
			Active:          os.Getenv("LDAP_URL") != "",
			URL:             os.Getenv("LDAP_URL"),
			BindDN:          os.Getenv("LDAP_BIND_DN"),
			BindPassword:    os.Getenv("LDAP_BIND_PASSWORD"),
			BaseDN:          os.Getenv("LDAP_BASE_DN"),
			LoginFilter:     env("LDAP_LOGIN_FILTER", "(uid=%s)"),
			SyncFilter:      os.Getenv("LDAP_SYNC_FILTER"),
			UsernameAttr:    env("LDAP_USERNAME_ATTRIBUTE", "uid"),
			DisplayNameAttr: env("LDAP_DISPLAY_NAME_ATTRIBUTE", "cn"),
			EmailAttr:       env("LDAP_EMAIL_ATTRIBUTE", "mail"),
			StartTLS:        envBool("LDAP_START_TLS", false),
		},
	}
	if err := httpapi.EnsureBootstrapAdmin(ctx, api, os.Getenv("BOOTSTRAP_ADMIN_USERNAME"), os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")); err != nil {
		slog.Error("bootstrap administrator failed", "error", err)
		os.Exit(1)
	}
	go api.StartNotificationLoop(ctx)
	go api.StartLoginProtectionCleanup(ctx)
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

func consoleSigningKey(secret string) []byte {
	if secret == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(secret))
	return hash[:]
}

func settingsEncryptionKey(secret string) []byte {
	if secret == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(secret))
	return hash[:]
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	return err == nil && parsed
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
