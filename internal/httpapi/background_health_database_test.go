package httpapi

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"vmp-backend/internal/platform"
)

func TestHealthSettingsDefaultSwitchAndCrossReplicaThrottleDatabase(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	api := &API{Service: &platform.Service{DB: db}, SettingsEncryptionKey: make([]byte, 32)}
	c, err := api.loadNotificationSettings(ctx, db)
	if err != nil || !c.NotifyPlatformHealth {
		t.Fatalf("默认开关错误 %v", err)
	}
	cipher, err := encryptSecret(api.SettingsEncryptionKey, []byte("https://robot.example/api/v1/webhook/send?key=private-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `UPDATE notification_settings SET enabled=true,webhook_ciphertext=$1`, cipher); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if err = api.EnqueueHealthAlert(ctx, "reconciler", 3, "后台操作失败"); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM platform_notification_outbox WHERE kind='PLATFORM_HEALTH'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("跨副本重复告警 %d %v", n, err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveHealthNotificationSetting(ctx, tx, false); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = api.EnqueueHealthAlert(ctx, "notifications", 3, "后台操作失败"); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM platform_notification_outbox WHERE kind='PLATFORM_HEALTH'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("关闭开关仍入队")
	}
	lock, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(ctx)
	if _, err = lock.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, notificationLock); err != nil {
		t.Fatal(err)
	}
	if _, err = api.beginNotification(ctx); !errors.Is(err, errNotificationBusy) {
		t.Fatalf("未区分锁竞争 %v", err)
	}
	if notificationBeginError(err) != nil {
		t.Fatal("竞争被当成故障")
	}
	if notificationBeginError(pgx.ErrTxClosed) == nil {
		t.Fatal("真实错误被吞掉")
	}
}
