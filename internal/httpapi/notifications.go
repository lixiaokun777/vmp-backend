package httpapi

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

const notificationLock = 8673221

type notificationSettings struct {
	Enabled            bool       `json:"enabled"`
	PlatformURL        string     `json:"platform_url"`
	ReminderHours      []int      `json:"reminder_hours"`
	NotifyRetained     bool       `json:"notify_retained"`
	NotifyRetentionEnd bool       `json:"notify_retention_end"`
	MentionOwner       bool       `json:"mention_owner"`
	EnabledSince       *time.Time `json:"enabled_since"`
	LastAttempt        *time.Time `json:"last_attempt_at"`
	LastSuccess        *time.Time `json:"last_success_at"`
	LastError          string     `json:"last_error"`
	WebhookURL         string     `json:"-"`
	SignatureSecret    string     `json:"-"`
	WebhookCipher      []byte     `json:"-"`
	SignatureCipher    []byte     `json:"-"`
}

type notificationQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (a *API) loadNotificationSettings(ctx context.Context, db notificationQuerier) (notificationSettings, error) {
	var c notificationSettings
	err := db.QueryRow(ctx, `SELECT enabled,webhook_ciphertext,signature_ciphertext,platform_url,reminder_hours,notify_retained,notify_retention_end,mention_owner,enabled_since,last_attempt_at,last_success_at,last_error FROM notification_settings WHERE singleton=true`).Scan(
		&c.Enabled, &c.WebhookCipher, &c.SignatureCipher, &c.PlatformURL, &c.ReminderHours, &c.NotifyRetained, &c.NotifyRetentionEnd, &c.MentionOwner, &c.EnabledSince, &c.LastAttempt, &c.LastSuccess, &c.LastError)
	if err != nil {
		return c, err
	}
	for _, item := range []struct {
		cipher []byte
		value  *string
	}{{c.WebhookCipher, &c.WebhookURL}, {c.SignatureCipher, &c.SignatureSecret}} {
		if len(item.cipher) == 0 {
			continue
		}
		plain, err := decryptSecret(a.SettingsEncryptionKey, item.cipher)
		if err != nil {
			return c, errors.New("通知密钥无法解密，请检查 SETTINGS_ENCRYPTION_KEY 是否与保存配置时一致")
		}
		*item.value = string(plain)
	}
	return c, nil
}

func notificationConfigResponse(c notificationSettings) map[string]any {
	endpoint := ""
	if parsed, err := url.Parse(c.WebhookURL); err == nil && parsed.Host != "" {
		endpoint = parsed.Scheme + "://" + parsed.Host + parsed.Path + "?key=******"
	}
	return map[string]any{"enabled": c.Enabled, "platform_url": c.PlatformURL, "reminder_hours": c.ReminderHours,
		"notify_retained": c.NotifyRetained, "notify_retention_end": c.NotifyRetentionEnd, "mention_owner": c.MentionOwner,
		"has_webhook": c.WebhookURL != "", "has_signature_secret": c.SignatureSecret != "", "webhook_display": endpoint,
		"last_attempt_at": c.LastAttempt, "last_success_at": c.LastSuccess, "last_error": c.LastError}
}

func (a *API) notificationConfig(w http.ResponseWriter, r *http.Request) {
	c, err := a.loadNotificationSettings(r.Context(), a.Service.DB)
	if err != nil {
		writeError(w, 500, "读取通知配置失败")
		return
	}
	writeJSON(w, 200, notificationConfigResponse(c))
}

func validateNotificationSettings(c notificationSettings) error {
	if len(c.ReminderHours) < 1 || len(c.ReminderHours) > 5 {
		return errors.New("请设置 1 至 5 个到期前提醒时间")
	}
	seen := make(map[int]bool)
	for _, hours := range c.ReminderHours {
		if hours < 1 || hours > 168 || seen[hours] {
			return errors.New("提醒时间必须是 1 至 168 的不重复整数小时")
		}
		seen[hours] = true
	}
	if c.WebhookURL != "" {
		u, err := url.Parse(c.WebhookURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || !strings.HasSuffix(u.Path, "/api/v1/webhook/send") || u.Query().Get("key") == "" {
			return errors.New("机器人地址必须是带 key 参数的 HTTPS Webhook 地址，路径以 /api/v1/webhook/send 结尾")
		}
	}
	if c.Enabled && c.WebhookURL == "" {
		return errors.New("启用通知前请先填写机器人 Webhook 地址")
	}
	if c.PlatformURL != "" {
		u, err := url.Parse(c.PlatformURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("平台访问地址必须是无账号、查询参数或片段的 HTTP(S) 地址")
		}
	}
	if len(c.WebhookURL) > 2048 || len(c.SignatureSecret) > 1024 || len(c.PlatformURL) > 512 {
		return errors.New("通知配置字段过长")
	}
	return nil
}

func (a *API) updateNotificationConfig(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled            bool   `json:"enabled"`
		WebhookURL         string `json:"webhook_url"`
		SignatureSecret    string `json:"signature_secret"`
		ClearWebhook       bool   `json:"clear_webhook"`
		ClearSignature     bool   `json:"clear_signature_secret"`
		PlatformURL        string `json:"platform_url"`
		ReminderHours      []int  `json:"reminder_hours"`
		NotifyRetained     bool   `json:"notify_retained"`
		NotifyRetentionEnd bool   `json:"notify_retention_end"`
		MentionOwner       bool   `json:"mention_owner"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&input) != nil {
		writeError(w, 400, "通知配置格式无效")
		return
	}
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, "无法保存通知配置")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock($1)`, notificationLock); err != nil {
		writeError(w, 500, "无法锁定通知配置")
		return
	}
	c, err := a.loadNotificationSettings(r.Context(), tx)
	if err != nil {
		writeError(w, 500, "读取通知配置失败")
		return
	}
	wasEnabled := c.Enabled
	c.Enabled, c.PlatformURL, c.ReminderHours = input.Enabled, strings.TrimRight(strings.TrimSpace(input.PlatformURL), "/"), input.ReminderHours
	c.NotifyRetained, c.NotifyRetentionEnd, c.MentionOwner = input.NotifyRetained, input.NotifyRetentionEnd, input.MentionOwner
	if input.ClearWebhook {
		c.WebhookURL, c.WebhookCipher = "", nil
	}
	if input.ClearSignature {
		c.SignatureSecret, c.SignatureCipher = "", nil
	}
	for _, item := range []struct {
		input  string
		value  *string
		cipher *[]byte
	}{
		{strings.TrimSpace(input.WebhookURL), &c.WebhookURL, &c.WebhookCipher}, {strings.TrimSpace(input.SignatureSecret), &c.SignatureSecret, &c.SignatureCipher},
	} {
		if item.input == "" {
			continue
		}
		cipher, err := encryptSecret(a.SettingsEncryptionKey, []byte(item.input))
		if err != nil {
			writeError(w, 422, "保存机器人地址或密钥前必须配置有效的 SETTINGS_ENCRYPTION_KEY")
			return
		}
		*item.value, *item.cipher = item.input, cipher
	}
	if err := validateNotificationSettings(c); err != nil {
		writeError(w, 422, err.Error())
		return
	}
	sort.Sort(sort.Reverse(sort.IntSlice(c.ReminderHours)))
	if c.Enabled && !wasEnabled {
		now := time.Now()
		c.EnabledSince = &now
	}
	user, _ := userFromRequest(r)
	_, err = tx.Exec(r.Context(), `UPDATE notification_settings SET enabled=$1,webhook_ciphertext=$2,signature_ciphertext=$3,platform_url=$4,reminder_hours=$5,notify_retained=$6,notify_retention_end=$7,mention_owner=$8,enabled_since=$9,updated_by=$10,updated_at=now() WHERE singleton=true`,
		c.Enabled, c.WebhookCipher, c.SignatureCipher, c.PlatformURL, c.ReminderHours, c.NotifyRetained, c.NotifyRetentionEnd, c.MentionOwner, c.EnabledSince, user.Username)
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		writeError(w, 500, "保存通知配置失败")
		return
	}
	writeJSON(w, 200, notificationConfigResponse(c))
}

// sendRobotMessage 使用文档规定的 MD5 和 SHA-1 签名算法，禁止跟随重定向泄露机器人密钥。
func sendRobotMessage(ctx context.Context, c notificationSettings, message string) error {
	if utf8.RuneCountInString(message) > 4500 {
		return errors.New("群消息超过安全长度限制")
	}
	payload, err := json.Marshal(map[string]any{"msgtype": "text", "text": map[string]string{"content": message}})
	if err != nil {
		return errors.New("无法构造群消息")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return errors.New("机器人地址无效")
	}
	req.Header.Set("Content-Type", "application/json")
	if c.SignatureSecret != "" {
		digest := md5.Sum(payload)
		contentMD5 := hex.EncodeToString(digest[:])
		date := time.Now().UTC().Format(http.TimeFormat)
		sign := sha1.Sum([]byte(c.SignatureSecret + contentMD5 + "application/json" + date))
		req.Header.Set("Content-Md5", contentMD5)
		req.Header.Set("Date", date)
		req.Header.Set("Authorization", req.URL.Query().Get("key")+":"+hex.EncodeToString(sign[:]))
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("连接群机器人失败，请检查 DNS、网络出口、TLS 证书和机器人地址")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("机器人返回 HTTP %d，请检查机器人地址、网络白名单和服务状态", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(body) > 65536 {
		return errors.New("读取机器人响应失败或响应过大")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(body, &response) != nil {
		return errors.New("机器人返回了无法识别的响应，请检查地址是否指向消息发送接口")
	}
	for _, name := range []string{"errcode", "code"} {
		if value, ok := response[name]; ok {
			var code int
			if json.Unmarshal(value, &code) != nil || (code != 0 && code != 200) {
				return errors.New("机器人拒绝消息，请检查机器人 key、签名、关键词和 IP 白名单")
			}
		}
	}
	if value, ok := response["result"]; ok {
		var result string
		if json.Unmarshal(value, &result) == nil && result != "ok" && result != "success" {
			return errors.New("机器人未确认消息发送成功，请检查机器人安全设置")
		}
	}
	if value, ok := response["success"]; ok && string(value) == "false" {
		return errors.New("机器人拒绝消息，请检查机器人安全设置")
	}
	return nil
}

type notificationInstance struct {
	ID, Name, Owner, DisplayName, Email, Status string
	ExpiresAt                                   time.Time
	RetentionUntil                              *time.Time
	UpdatedAt                                   time.Time
}

type notificationCandidate struct {
	Instance notificationInstance
	Kind     string
	TargetAt time.Time
}

// reminderCandidate 仅选择当前最紧急的阶段，续期、释放和删除后旧事件将被取消。
func reminderCandidate(c notificationSettings, i notificationInstance, now time.Time) *notificationCandidate {
	if i.Status == "RETAINED" && i.RetentionUntil != nil && i.RetentionUntil.After(now) {
		if c.NotifyRetentionEnd && i.RetentionUntil.Sub(now) <= 24*time.Hour {
			return &notificationCandidate{i, "RETENTION_END", *i.RetentionUntil}
		}
		if c.NotifyRetained && c.EnabledSince != nil && !i.UpdatedAt.Before(*c.EnabledSince) {
			return &notificationCandidate{i, "RETAINED", *i.RetentionUntil}
		}
		return nil
	}
	if i.Status != "RUNNING" && i.Status != "STOPPED" && i.Status != "STARTING" && i.Status != "REBOOTING" {
		return nil
	}
	remaining := i.ExpiresAt.Sub(now)
	if remaining <= 0 {
		return nil
	}
	threshold := 169
	for _, hours := range c.ReminderHours {
		if remaining <= time.Duration(hours)*time.Hour && hours < threshold {
			threshold = hours
		}
	}
	if threshold == 169 {
		return nil
	}
	return &notificationCandidate{i, "LEASE_" + strconv.Itoa(threshold), i.ExpiresAt}
}

func notificationText(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	value = strings.NewReplacer("<", "＜", ">", "＞", "@", "＠").Replace(value)
	runes := []rune(value)
	if len(runes) > 64 {
		value = string(runes[:64]) + "…"
	}
	return value
}

func notificationMessage(c notificationSettings, items []notificationCandidate, now time.Time) string {
	var b strings.Builder
	b.WriteString("【北斗云台】虚拟机租期提醒\n")
	zone := time.FixedZone("Asia/Shanghai", 8*3600)
	for _, item := range items {
		i := item.Instance
		owner := notificationText(i.DisplayName)
		if owner == "" {
			owner = notificationText(i.Owner)
		}
		owner += "（" + notificationText(i.Owner) + "）"
		if email, err := mail.ParseAddress(i.Email); c.MentionOwner && len(i.Email) <= 254 && err == nil && email.Address == i.Email {
			owner = `<at email="` + html.EscapeString(email.Address) + `">` + html.EscapeString(owner) + `</at>`
		}
		fmt.Fprintf(&b, "\n实例：%s\n使用人：%s\n", notificationText(i.Name), owner)
		switch item.Kind {
		case "RETAINED":
			fmt.Fprintf(&b, "状态：已进入保留期，原磁盘和 IP 仍保留\n最终删除时间：%s\n请及时进入平台恢复或确认不再使用。\n", item.TargetAt.In(zone).Format("2006-01-02 15:04:05"))
		case "RETENTION_END":
			fmt.Fprintf(&b, "状态：保留期将在 24 小时内结束\n最终删除时间：%s\n届时磁盘将被删除并释放 IP，请立即恢复或备份所需数据。\n", item.TargetAt.In(zone).Format("2006-01-02 15:04:05"))
		default:
			minutes := int(item.TargetAt.Sub(now).Minutes())
			if minutes < 1 {
				minutes = 1
			}
			remaining := fmt.Sprintf("%d 分钟", minutes)
			if minutes >= 60 {
				remaining = fmt.Sprintf("%d 小时 %d 分钟", minutes/60, minutes%60)
			}
			fmt.Fprintf(&b, "到期时间：%s（北京时间）\n剩余：%s\n请提前续期；超过 7 天的续期需要管理员审批。\n", item.TargetAt.In(zone).Format("2006-01-02 15:04:05"), remaining)
		}
	}
	if c.PlatformURL != "" {
		fmt.Fprintf(&b, "\n前往我的虚拟机：%s/#/my-instances\n", c.PlatformURL)
	}
	b.WriteString("\n普通到期回收会保留原磁盘和 IP 7 天；已恢复过一次的实例不再享受第二次保留期。群消息不会包含密码或控制台票据。")
	return b.String()
}

func (a *API) beginNotification(ctx context.Context) (pgx.Tx, error) {
	tx, err := a.Service.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, notificationLock).Scan(&locked); err != nil || !locked {
		tx.Rollback(ctx)
		return nil, errors.New("通知任务正在执行，请稍后重试")
	}
	return tx, nil
}

func (a *API) testNotification(w http.ResponseWriter, r *http.Request) {
	tx, err := a.beginNotification(r.Context())
	if err != nil {
		writeError(w, 409, "通知任务正在执行，请稍后重试")
		return
	}
	defer tx.Rollback(r.Context())
	c, err := a.loadNotificationSettings(r.Context(), tx)
	if err != nil || c.WebhookURL == "" {
		writeError(w, 422, "请先保存有效的机器人配置")
		return
	}
	if c.LastAttempt != nil && time.Since(*c.LastAttempt) < 3*time.Second {
		writeError(w, 429, "测试消息发送过于频繁，请等待至少 3 秒")
		return
	}
	message := "【北斗云台】群通知测试\n这是一条管理员主动发送的测试消息。收到此消息说明平台服务器到群机器人的发送链路正常。此消息不会修改虚拟机租期。"
	user, _ := userFromRequest(r)
	now := time.Now()
	err = sendRobotMessage(r.Context(), c, message)
	status, errorText := "SENT", ""
	if err != nil {
		status, errorText = "FAILED", err.Error()
	}
	_, dbErr := tx.Exec(r.Context(), `INSERT INTO notification_events(kind,target_at,owner_username,status,attempts,last_error,message,sent_at) VALUES('TEST',$1,$2,$3,1,$4,$5,CASE WHEN $3='SENT' THEN now() ELSE NULL END)`, now, user.Username, status, errorText, message)
	if dbErr == nil {
		dbErr = saveNotificationAttempt(r.Context(), tx, errorText)
	}
	if dbErr == nil {
		dbErr = tx.Commit(r.Context())
	}
	if dbErr != nil {
		writeError(w, 500, "测试已执行但发送记录保存失败，请检查数据库后再测试")
		return
	}
	if err != nil {
		writeError(w, 502, errorText)
		return
	}
	writeJSON(w, 200, map[string]any{"message": "测试消息已发送，请在群聊中确认是否收到"})
}

func saveNotificationAttempt(ctx context.Context, tx pgx.Tx, errorText string) error {
	_, err := tx.Exec(ctx, `UPDATE notification_settings SET last_attempt_at=now(),last_success_at=CASE WHEN $1='' THEN now() ELSE last_success_at END,last_error=$1 WHERE singleton=true`, errorText)
	return err
}

func (a *API) notificationEvents(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	filter := r.URL.Query().Get("status")
	if filter != "" && filter != "PENDING" && filter != "SENT" && filter != "FAILED" && filter != "CANCELLED" {
		writeError(w, 422, "通知状态无效")
		return
	}
	var total int
	if err := a.Service.DB.QueryRow(r.Context(), `SELECT count(*) FROM notification_events WHERE ($1='' OR status=$1)`, filter).Scan(&total); err != nil {
		writeError(w, 500, "读取通知记录失败")
		return
	}
	page = min(page, max(1, (total+19)/20))
	rows, err := a.Service.DB.Query(r.Context(), `SELECT jsonb_build_object('id',id,'kind',kind,'instance_name',instance_name,'owner',owner_username,'status',status,'attempts',attempts,'target_at',target_at,'last_error',last_error,'message',message,'created_at',created_at,'sent_at',sent_at,'next_attempt_at',next_attempt_at) FROM notification_events WHERE ($1='' OR status=$1) ORDER BY created_at DESC,id DESC LIMIT 20 OFFSET $2`, filter, (page-1)*20)
	if err != nil {
		writeError(w, 500, "读取通知记录失败")
		return
	}
	defer rows.Close()
	items := make([]json.RawMessage, 0)
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			writeError(w, 500, "读取通知记录失败")
			return
		}
		items = append(items, json.RawMessage(data))
	}
	if rows.Err() != nil {
		writeError(w, 500, "读取通知记录失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": 20})
}

// StartNotificationLoop 每分钟执行一次；数据库锁保证多个控制面副本不会同时发送。
func (a *API) StartNotificationLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := a.dispatchNotifications(runCtx); err != nil {
			slog.Error("群通知任务执行失败", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func candidateKey(id, kind string, target time.Time) string {
	return id + ":" + kind + ":" + target.UTC().Format(time.RFC3339Nano)
}

func (a *API) dispatchNotifications(ctx context.Context) error {
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
	now := time.Now()
	rows, err := tx.Query(ctx, `SELECT i.id::text,i.name,a.applicant,coalesce(u.display_name,''),coalesce(u.email,''),i.lifecycle_status,i.expires_at,i.retention_until,i.updated_at FROM instances i JOIN applications a ON a.id=i.application_id LEFT JOIN users u ON lower(u.username)=lower(a.applicant) WHERE i.lifecycle_status IN ('RUNNING','STOPPED','STARTING','REBOOTING','RETAINED') ORDER BY coalesce(i.retention_until,i.expires_at),i.id`)
	if err != nil {
		return err
	}
	var candidates []notificationCandidate
	byKey := make(map[string]notificationCandidate)
	for rows.Next() {
		var i notificationInstance
		if err := rows.Scan(&i.ID, &i.Name, &i.Owner, &i.DisplayName, &i.Email, &i.Status, &i.ExpiresAt, &i.RetentionUntil, &i.UpdatedAt); err != nil {
			rows.Close()
			return err
		}
		if candidate := reminderCandidate(c, i, now); candidate != nil {
			candidates = append(candidates, *candidate)
			byKey[candidateKey(i.ID, candidate.Kind, candidate.TargetAt)] = *candidate
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range candidates {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_events(instance_id,kind,target_at,instance_name,owner_username) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(instance_id,kind,target_at) DO NOTHING`, item.Instance.ID, item.Kind, item.TargetAt, item.Instance.Name, item.Instance.Owner); err != nil {
			return err
		}
	}
	rows, err = tx.Query(ctx, `SELECT id::text,instance_id::text,kind,target_at,attempts,next_attempt_at FROM notification_events WHERE status='PENDING' ORDER BY target_at,created_at,id`)
	if err != nil {
		return err
	}
	var stale, sendIDs []string
	var sendItems []notificationCandidate
	var attempts []int
	for rows.Next() {
		var id, instanceID, kind string
		var target, next time.Time
		var attempt int
		if err := rows.Scan(&id, &instanceID, &kind, &target, &attempt, &next); err != nil {
			rows.Close()
			return err
		}
		item, exists := byKey[candidateKey(instanceID, kind, target)]
		if !exists {
			stale = append(stale, id)
			continue
		}
		if len(sendIDs) < 10 && !next.After(now) && utf8.RuneCountInString(notificationMessage(c, append(append([]notificationCandidate{}, sendItems...), item), now)) <= 4500 {
			sendIDs = append(sendIDs, id)
			sendItems = append(sendItems, item)
			attempts = append(attempts, attempt)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(stale) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE notification_events SET status='CANCELLED',last_error='租期或实例状态已改变，取消旧提醒' WHERE id=ANY($1::uuid[])`, stale); err != nil {
			return err
		}
	}
	if len(sendIDs) == 0 || (c.LastAttempt != nil && now.Sub(*c.LastAttempt) < time.Minute) {
		return tx.Commit(ctx)
	}
	// 只锁定本轮将发送的实例，防止用户正在续期时发出已经过时的消息。
	instanceIDs := make([]string, len(sendItems))
	for index, item := range sendItems {
		instanceIDs[index] = item.Instance.ID
	}
	rows, err = tx.Query(ctx, `SELECT i.id::text,i.name,a.applicant,coalesce(u.display_name,''),coalesce(u.email,''),i.lifecycle_status,i.expires_at,i.retention_until,i.updated_at FROM instances i JOIN applications a ON a.id=i.application_id LEFT JOIN users u ON lower(u.username)=lower(a.applicant) WHERE i.id=ANY($1::uuid[]) FOR SHARE OF i`, instanceIDs)
	if err != nil {
		return err
	}
	valid := make(map[string]notificationCandidate)
	for rows.Next() {
		var i notificationInstance
		if err := rows.Scan(&i.ID, &i.Name, &i.Owner, &i.DisplayName, &i.Email, &i.Status, &i.ExpiresAt, &i.RetentionUntil, &i.UpdatedAt); err != nil {
			rows.Close()
			return err
		}
		if item := reminderCandidate(c, i, time.Now()); item != nil {
			valid[candidateKey(i.ID, item.Kind, item.TargetAt)] = *item
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	keptIDs, keptItems, keptAttempts := []string{}, []notificationCandidate{}, []int{}
	for index, item := range sendItems {
		if current, ok := valid[candidateKey(item.Instance.ID, item.Kind, item.TargetAt)]; ok {
			keptIDs = append(keptIDs, sendIDs[index])
			keptItems = append(keptItems, current)
			keptAttempts = append(keptAttempts, attempts[index])
		} else {
			if _, err := tx.Exec(ctx, `UPDATE notification_events SET status='CANCELLED',last_error='发送前租期或实例状态已改变' WHERE id=$1::uuid`, sendIDs[index]); err != nil {
				return err
			}
		}
	}
	sendIDs, sendItems, attempts = keptIDs, keptItems, keptAttempts
	if len(sendIDs) == 0 {
		return tx.Commit(ctx)
	}
	message := notificationMessage(c, sendItems, now)
	sendErr := sendRobotMessage(ctx, c, message)
	errorText := ""
	if sendErr != nil {
		errorText = sendErr.Error()
	}
	for index, id := range sendIDs {
		if sendErr == nil {
			_, err = tx.Exec(ctx, `UPDATE notification_events SET status='SENT',attempts=attempts+1,message=$2,sent_at=now(),last_error='' WHERE id=$1::uuid`, id, message)
		} else {
			attempt := attempts[index] + 1
			status := "PENDING"
			if attempt >= 5 {
				status = "FAILED"
			}
			delays := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, 60 * time.Minute}
			_, err = tx.Exec(ctx, `UPDATE notification_events SET status=$2,attempts=$3,last_error=$4,message=$5,next_attempt_at=$6 WHERE id=$1::uuid`, id, status, attempt, errorText, message, now.Add(delays[min(attempt-1, 4)]))
		}
		if err != nil {
			return err
		}
	}
	if err := saveNotificationAttempt(ctx, tx, errorText); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
