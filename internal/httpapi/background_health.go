package httpapi

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"vmp-backend/internal/background"
)

// 复用现有队列的一条取消发送的配置记录，不增加既有表字段；该行不生成通知历史。
const healthSettingsKey = "platform-health-settings"

func (a *API) EnqueueHealthAlert(ctx context.Context, loop string, count int, summary string) error {
	tx, err := a.beginNotification(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	c, err := a.loadNotificationSettings(ctx, tx)
	if err != nil {
		return err
	}
	if !c.Enabled || c.WebhookURL == "" || !c.NotifyPlatformHealth {
		slog.Debug("平台健康告警未启用渠道", "loop", loop)
		return nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO platform_notification_outbox(event_key,kind,resource_id,title,detail) VALUES($1,'PLATFORM_HEALTH',$2,'平台健康告警',$3) ON CONFLICT(event_key) DO UPDATE SET title=excluded.title,detail=excluded.detail,status='PENDING',attempts=0,next_attempt_at=now(),last_error='',created_at=now(),sent_at=NULL WHERE platform_notification_outbox.created_at<=now()-interval '30 minutes' AND platform_notification_outbox.status<>'PENDING'`, "platform-health:"+loop, loop, background.Detail(loop, count, summary))
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func notificationBeginError(err error) error {
	if errors.Is(err, errNotificationBusy) {
		slog.Debug("通知锁由其他副本持有，本轮跳过")
		return nil
	}
	slog.Error("通知事务启动失败", "error", err)
	return err
}

func saveHealthNotificationSetting(ctx context.Context, tx pgx.Tx, enabled bool) error {
	detail := "disabled"
	if enabled {
		detail = "enabled"
	}
	_, err := tx.Exec(ctx, `INSERT INTO platform_notification_outbox(event_key,kind,resource_id,title,detail,status) VALUES($1,'PLATFORM_HEALTH_SETTINGS','notifications','平台健康告警设置',$2,'CANCELLED') ON CONFLICT(event_key) DO UPDATE SET detail=excluded.detail`, healthSettingsKey, detail)
	return err
}
