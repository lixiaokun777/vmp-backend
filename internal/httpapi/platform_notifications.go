package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// 队列只收集启用之后的新审批/失败和宿主异常边沿；不把每次心跳发到群里。
func collectPlatformEvents(ctx context.Context, tx pgx.Tx, c notificationSettings) error {
	if c.EnabledSince == nil {
		return nil
	}
	statements := []struct {
		enabled bool
		sql     string
	}{
		{c.NotifyApprovals, `INSERT INTO platform_notification_outbox(event_key,kind,resource_id,title,detail) SELECT 'approval-pending:'||id::text,'APPROVAL_PENDING',id::text,'有新的长租期审批',request_no||' · 申请人：'||applicant||' · 租期：'||requested_hours||' 小时 · 审批员：'||coalesce(assigned_reviewer,'任一管理员') FROM approval_requests WHERE status='PENDING' AND expires_at>now() AND created_at>=$1 ON CONFLICT(event_key) DO NOTHING`},
		{c.NotifyFailures, `INSERT INTO platform_notification_outbox(event_key,kind,resource_id,title,detail) SELECT 'approval-failed:'||id::text,'APPROVAL_FAILED',id::text,'审批通过后的执行失败',request_no||' · 申请人：'||applicant||' · 请进入审批详情查看原因和关联任务' FROM approval_requests WHERE status IN ('FAILED','APPROVED_FAILED') AND updated_at>=greatest($1::timestamptz,now()-interval '24 hours') ON CONFLICT(event_key) DO NOTHING`},
		{c.NotifyFailures, `INSERT INTO platform_notification_outbox(event_key,kind,resource_id,title,detail) SELECT 'delivery-failed:'||t.id::text||':'||t.attempt,'DELIVERY_FAILED',t.resource_id::text,'虚拟机交付失败',coalesce(i.name,'实例已删除')||' · 使用人：'||coalesce(ap.applicant,'未知')||' · 请进入实例详情查看错误并重试/救援' FROM tasks t LEFT JOIN instances i ON i.id=t.resource_id LEFT JOIN applications ap ON ap.id=i.application_id WHERE t.task_type IN ('CREATE_INSTANCE','START_INSTANCE') AND t.status='FAILED' AND t.updated_at>=greatest($1::timestamptz,now()-interval '24 hours') ON CONFLICT(event_key) DO NOTHING`},
	}
	for _, item := range statements {
		if item.enabled {
			if _, err := tx.Exec(ctx, item.sql, *c.EnabledSince); err != nil {
				return err
			}
		}
	}
	rows, err := tx.Query(ctx, `SELECT h.id::text,h.name,(h.last_heartbeat_at IS NULL OR h.last_heartbeat_at<now()-interval '120 seconds' OR h.status='OFFLINE'),st.offline FROM hosts h LEFT JOIN host_notification_state st ON st.host_id=h.id WHERE h.agent_mode<>'mock' ORDER BY h.id`)
	if err != nil {
		return err
	}
	type hostState struct {
		id, name string
		offline  bool
		old      *bool
	}
	var hosts []hostState
	for rows.Next() {
		var h hostState
		if err = rows.Scan(&h.id, &h.name, &h.offline, &h.old); err != nil {
			rows.Close()
			return err
		}
		hosts = append(hosts, h)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, h := range hosts {
		changed := h.old != nil && *h.old != h.offline
		// 初次启用时只播报当前故障一次，健康宿主仅建立基线，不产生恢复噪声。
		if c.NotifyHostAlerts && (changed || h.old == nil && h.offline) {
			kind, title, detail := "HOST_RECOVERED", "宿主 Agent 已恢复", "心跳已恢复，请检查宿主安全检查和调度状态"
			if h.offline {
				kind, title, detail = "HOST_OFFLINE", "宿主 Agent 心跳异常", "已超过 120 秒未收到心跳；不会自动删除任何虚拟机，请管理员检查服务和网络"
			}
			key := fmt.Sprintf("host:%s:%s:%d", h.id, kind, time.Now().UnixNano())
			if _, err = tx.Exec(ctx, `INSERT INTO platform_notification_outbox(event_key,kind,resource_id,title,detail) VALUES($1,$2,$3,$4,$5)`, key, kind, h.id, title, h.name+" · "+detail); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO host_notification_state(host_id,offline) VALUES($1::uuid,$2) ON CONFLICT(host_id) DO UPDATE SET offline=excluded.offline,transition_at=CASE WHEN host_notification_state.offline<>excluded.offline THEN now() ELSE host_notification_state.transition_at END`, h.id, h.offline); err != nil {
			return err
		}
	}
	return nil
}

func platformEventEnabled(c notificationSettings, kind string) bool {
	switch kind {
	case "APPROVAL_PENDING":
		return c.NotifyApprovals
	case "APPROVAL_FAILED", "DELIVERY_FAILED":
		return c.NotifyFailures
	case "HOST_OFFLINE", "HOST_RECOVERED":
		return c.NotifyHostAlerts
	}
	return false
}

func (a *API) dispatchPlatformNotifications(ctx context.Context) error {
	tx, err := a.beginNotification(ctx)
	if err != nil {
		return nil
	}
	defer tx.Rollback(ctx)
	c, err := a.loadNotificationSettings(ctx, tx)
	if err != nil {
		return err
	}
	if !c.Enabled || c.WebhookURL == "" {
		return nil
	}
	if err = collectPlatformEvents(ctx, tx, c); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id::text,kind,resource_id,title,detail,attempts,created_at FROM platform_notification_outbox WHERE status='PENDING' AND next_attempt_at<=now() ORDER BY created_at,id LIMIT 10 FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return err
	}
	type event struct {
		id, kind, resource, title, detail string
		attempt                           int
		created                           time.Time
	}
	var events []event
	for rows.Next() {
		var e event
		if err = rows.Scan(&e.id, &e.kind, &e.resource, &e.title, &e.detail, &e.attempt, &e.created); err != nil {
			rows.Close()
			return err
		}
		events = append(events, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var kept []event
	for _, e := range events {
		if !platformEventEnabled(c, e.kind) {
			if _, err = tx.Exec(ctx, `UPDATE platform_notification_outbox SET status='CANCELLED',last_error='管理员已关闭此类通知' WHERE id=$1::uuid`, e.id); err != nil {
				return err
			}
		} else {
			kept = append(kept, e)
		}
	}
	events = kept
	if len(events) == 0 || c.LastAttempt != nil && time.Since(*c.LastAttempt) < time.Minute {
		return tx.Commit(ctx)
	}
	var b strings.Builder
	b.WriteString("## 🔔 【北斗云台】平台操作提醒\n\n")
	for _, e := range events {
		fmt.Fprintf(&b, "### %s\n\n> %s\n\n", notificationText(e.title), platformDetailText(e.detail))
	}
	if c.PlatformURL != "" {
		b.WriteString("[打开平台处理](" + notificationPlatformLink(c.PlatformURL) + ")\n\n")
	}
	b.WriteString("> 群内不包含密码、令牌或控制台票据。审批与故障详情需登录后查看。")
	message := b.String()
	sendErr := sendRobotMessage(ctx, c, message)
	errorText := ""
	if sendErr != nil {
		errorText = sendErr.Error()
	}
	for _, e := range events {
		status := "SENT"
		if sendErr != nil {
			status = "PENDING"
			if e.attempt+1 >= 5 {
				status = "FAILED"
			}
		}
		delays := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, 60 * time.Minute}
		next := time.Now().Add(delays[min(e.attempt, 4)])
		if _, err = tx.Exec(ctx, `UPDATE platform_notification_outbox SET status=$2,attempts=attempts+1,last_error=$3,next_attempt_at=$4,sent_at=CASE WHEN $2='SENT' THEN now() ELSE NULL END WHERE id=$1::uuid`, e.id, status, errorText, next); err != nil {
			return err
		}
		logStatus := status
		if status == "PENDING" {
			logStatus = "FAILED"
		}
		if _, err = tx.Exec(ctx, `INSERT INTO notification_events(instance_id,kind,target_at,instance_name,status,attempts,last_error,message,sent_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $5='SENT' THEN now() ELSE NULL END) ON CONFLICT(instance_id,kind,target_at) DO UPDATE SET status=excluded.status,attempts=excluded.attempts,last_error=excluded.last_error,message=excluded.message,sent_at=excluded.sent_at`, e.id, e.kind, e.created, e.title, logStatus, e.attempt+1, errorText, message); err != nil {
			return err
		}
	}
	if err = saveNotificationAttempt(ctx, tx, errorText); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func platformDetailText(value string) string {
	var parts []string
	for _, part := range strings.Split(value, " · ") {
		parts = append(parts, notificationText(part))
	}
	return strings.Join(parts, " · ")
}

// 治理后台只更新审批路由和已授权续期，不做历史自动删除。
func (a *API) StartGovernanceLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := a.Service.RefreshDelegations(runCtx); err == nil {
			if err := a.Service.RunAutoRenew(runCtx); err != nil {
				slog.Error("自动续期检查失败", "error", err)
			}
		} else {
			slog.Error("审批代理路由检查失败", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
