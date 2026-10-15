package httpapi

import (
	"context"
	"testing"
	"vmp-backend/internal/migrate"
)

func TestUpgrade022To023IndexAndChecksumDatabase(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `DROP INDEX instance_metrics_collected_at_idx;DELETE FROM schema_migrations WHERE version='023_instance_metrics_collected_at_idx.sql'`); err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(ctx, db); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('instance_metrics_collected_at_idx') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatal("旧库升级缺少清理索引")
	}
	if err := migrate.Run(ctx, db); err != nil {
		t.Fatal("重复启动迁移失败", err)
	}
}
