// Package migrate 负责在控制面启动前安全地执行数据库迁移。
package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vmp-backend/migrations"
)

const advisoryLockID int64 = 24287251772376914

type migrationFile struct {
	name     string
	sql      string
	checksum string
}

// Run 串行执行尚未应用的迁移，并校验已经执行过的迁移没有被修改。
func Run(ctx context.Context, pool *pgxpool.Pool) error {
	files, err := loadFiles()
	if err != nil {
		return err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, unlockErr := conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, advisoryLockID); unlockErr != nil {
			slog.Warn("database migration lock release failed", "error", unlockErr)
		}
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY,
			checksum text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	applied := 0
	for _, file := range files {
		var recordedChecksum string
		err := conn.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, file.name).Scan(&recordedChecksum)
		switch {
		case err == nil:
			if recordedChecksum != file.checksum {
				return fmt.Errorf("migration %s checksum mismatch", file.name)
			}
			continue
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("read migration %s state: %w", file.name, err)
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", file.name, err)
		}
		if _, err := tx.Exec(ctx, file.sql); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", file.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version, checksum) VALUES($1,$2)`, file.name, file.checksum); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", file.name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", file.name, err)
		}
		applied++
		slog.Info("database migration applied", "version", file.name)
	}

	slog.Info("database migrations ready", "total", len(files), "applied", applied)
	return nil
}

func loadFiles() ([]migrationFile, error) {
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, errors.New("no embedded database migrations found")
	}

	files := make([]migrationFile, 0, len(names))
	for _, name := range names {
		if filepath.Base(name) != name {
			return nil, fmt.Errorf("invalid migration file name %q", name)
		}
		body, err := fs.ReadFile(migrations.Files, name)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", name, err)
		}
		digest := sha256.Sum256(body)
		files = append(files, migrationFile{
			name:     name,
			sql:      string(body),
			checksum: hex.EncodeToString(digest[:]),
		})
	}
	return files, nil
}
