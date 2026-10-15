package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vmp-backend/internal/background"
	"vmp-backend/internal/platform"
)

func TestHealthFailureUsesExistingRobotOutboxWithoutSecretsDatabase(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	var messages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		messages = append(messages, string(body))
		io.WriteString(w, `{"result":"ok"}`)
	}))
	defer server.Close()
	api := &API{Service: &platform.Service{DB: db}, SettingsEncryptionKey: make([]byte, 32)}
	cipher, err := encryptSecret(api.SettingsEncryptionKey, []byte(server.URL+"?key=PrivateRobotSecret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `UPDATE notification_settings SET enabled=true,webhook_ciphertext=$1`, cipher); err != nil {
		t.Fatal(err)
	}
	monitor := &background.Monitor{Enqueue: api.EnqueueHealthAlert}
	for range 3 {
		monitor.Observe(ctx, "reconciler", errors.New("postgres://admin:PrivateDBSecret@host/vmp token=PrivateTokenSecret"))
	}
	if err = api.dispatchPlatformNotifications(ctx); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || !strings.Contains(messages[0], "平台健康告警") || !strings.Contains(messages[0], "reconciler") {
		t.Fatal("健康告警未沿既有发送链路交付")
	}
	for _, v := range []string{"PrivateRobotSecret", "PrivateDBSecret", "PrivateTokenSecret", "postgres://"} {
		if strings.Contains(messages[0], v) {
			t.Fatal("群消息泄漏凭据")
		}
	}
	// 模拟另一控制面副本同时观察到故障，数据库节流仍只保留一个事件。
	other := &background.Monitor{Enqueue: api.EnqueueHealthAlert}
	for range 3 {
		other.Observe(ctx, "reconciler", errors.New("故障"))
	}
	var n int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM platform_notification_outbox WHERE kind='PLATFORM_HEALTH'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("跨副本产生重复告警")
	}
}
