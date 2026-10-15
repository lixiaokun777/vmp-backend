package background

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFailureThresholdThrottleRecoveryAndSecretSummary(t *testing.T) {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	var messages []string
	enabled := true
	m := &Monitor{Now: func() time.Time { return now }, Enqueue: func(_ context.Context, name string, count int, summary string) error {
		if enabled {
			messages = append(messages, Detail(name, count, summary))
		}
		return nil
	}}
	err := errors.New("postgres://admin:SecretPass@db/vmp?token=SecretToken DSN password=SecretKey")
	for range 2 {
		m.Observe(context.Background(), "reconciler", err)
	}
	if len(messages) != 0 {
		t.Fatal("未达三轮便告警")
	}
	m.Observe(context.Background(), "reconciler", err)
	for range 10 {
		m.Observe(context.Background(), "reconciler", err)
	}
	if len(messages) != 1 {
		t.Fatal("三轮阈值或节流失败")
	}
	now = now.Add(30 * time.Minute)
	m.Observe(context.Background(), "reconciler", err)
	if len(messages) != 2 {
		t.Fatal("三十分钟后未恢复告警")
	}
	for _, secret := range []string{"SecretPass", "SecretToken", "SecretKey", "postgres://", "DSN"} {
		if strings.Contains(strings.Join(messages, ""), secret) {
			t.Fatal("告警泄漏敏感信息")
		}
	}
	m.Observe(context.Background(), "reconciler", nil)
	if m.states["reconciler"].count != 0 {
		t.Fatal("成功后没有复位")
	}
	enabled = false
	for range 3 {
		m.Observe(context.Background(), "notifications", err)
	}
	if len(messages) != 2 {
		t.Fatal("关闭开关仍产生通知")
	}
}
