package httpapi

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"vmp-backend/internal/platform"
	"vmp-backend/migrations"
)

func TestNotificationSignatureAndRejection(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		md := md5.Sum(body)
		digest := hex.EncodeToString(md[:])
		if r.Header.Get("Content-Md5") != digest {
			t.Error("消息摘要不匹配")
		}
		sign := sha1.Sum([]byte("secret" + digest + "application/json" + r.Header.Get("Date")))
		if r.Header.Get("Authorization") != "robot-key:"+hex.EncodeToString(sign[:]) {
			t.Error("签名不匹配")
		}
		if _, err := time.Parse(http.TimeFormat, r.Header.Get("Date")); err != nil {
			t.Error(err)
		}
		var payload struct {
			Msgtype  string `json:"msgtype"`
			Markdown struct {
				Text string `json:"text"`
			} `json:"markdown"`
		}
		if json.Unmarshal(body, &payload) != nil || payload.Msgtype != "markdown" || payload.Markdown.Text != "【北斗云台】测试" {
			t.Error("消息格式不匹配")
		}
		if count.Add(1) == 1 {
			io.WriteString(w, `{"result":"ok"}`)
		} else {
			io.WriteString(w, `{"errcode":403,"message":"含机器人密钥的错误"}`)
		}
	}))
	defer server.Close()
	c := notificationSettings{WebhookURL: server.URL + "?key=robot-key", SignatureSecret: "secret"}
	if err := sendRobotMessage(context.Background(), c, "【北斗云台】测试"); err != nil {
		t.Fatal(err)
	}
	if err := sendRobotMessage(context.Background(), c, "【北斗云台】测试"); err == nil || strings.Contains(err.Error(), "robot-key") || strings.Contains(err.Error(), "含机器人密钥") {
		t.Fatalf("错误处理失败：%v", err)
	}
}

func TestNotificationRedirectDoesNotLeakKey(t *testing.T) {
	var reached atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer server.Close()
	if sendRobotMessage(context.Background(), notificationSettings{WebhookURL: server.URL + "?key=secret"}, "测试") == nil || reached.Load() {
		t.Fatal("未阻止重定向")
	}
}

func TestNotificationStagesAndConfiguration(t *testing.T) {
	now := time.Now()
	c := notificationSettings{ReminderHours: []int{24, 1}, NotifyRetained: true, NotifyRetentionEnd: true, EnabledSince: &now}
	for _, test := range []struct {
		hours        time.Duration
		status, kind string
	}{
		{25 * time.Hour, "RUNNING", ""}, {2 * time.Hour, "RUNNING", "LEASE_24"}, {30 * time.Minute, "STOPPED", "LEASE_1"},
		{-time.Minute, "RUNNING", ""}, {30 * time.Minute, "DELETING", ""}, {30 * time.Minute, "RELEASED", ""},
	} {
		i := notificationInstance{Status: test.status, ExpiresAt: now.Add(test.hours)}
		item := reminderCandidate(c, i, now)
		if (item == nil && test.kind != "") || (item != nil && item.Kind != test.kind) {
			t.Fatalf("阶段选择错误：%+v，%+v", test, item)
		}
	}
	retention := now.Add(7 * 24 * time.Hour)
	i := notificationInstance{Status: "RETAINED", RetentionUntil: &retention, UpdatedAt: now}
	if reminderCandidate(c, i, now).Kind != "RETAINED" {
		t.Fatal("缺少保留期提醒")
	}
	retention = now.Add(20 * time.Hour)
	if reminderCandidate(c, i, now).Kind != "RETENTION_END" {
		t.Fatal("缺少最终删除提醒")
	}
	c.WebhookURL = "https://imwork.example.com:8663/woa/api/v1/webhook/send?key=secret"
	if err := validateNotificationSettings(c); err != nil {
		t.Fatal(err)
	}
	response, _ := json.Marshal(notificationConfigResponse(c))
	if strings.Contains(string(response), "key=secret") {
		t.Fatal("配置响应泄露机器人密钥")
	}
	c.ReminderHours = []int{1, 1}
	if validateNotificationSettings(c) == nil {
		t.Fatal("重复提醒时间应被拒绝")
	}
}

func TestNotificationMessageEscapesMentions(t *testing.T) {
	now := time.Now()
	c := notificationSettings{PlatformURL: "https://vmp.example.com", MentionOwner: true}
	i := notificationInstance{Name: `bad<at user_id="-1">all</at>`, Owner: "user", Email: "user@example.com"}
	message := notificationMessage(c, []notificationCandidate{{i, "LEASE_1", now.Add(time.Hour)}}, now)
	if strings.Contains(message, `<at user_id="-1">`) || !strings.Contains(message, `<at email="user@example.com">`) {
		t.Fatal("未正确限制用户输入的 @ 标签")
	}
	if !strings.Contains(message, "/#/my-instances") {
		t.Fatal("缺少平台链接")
	}
}

func TestNotificationMarkdownLayout(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	c := notificationSettings{PlatformURL: "https://vmp.example.com/path(x)", MentionOwner: true}
	items := []notificationCandidate{
		{Instance: notificationInstance{Name: "dev-api", Owner: "alice", DisplayName: "张三", Email: "alice@example.com"}, Kind: "LEASE_1", TargetAt: now.Add(30 * time.Minute)},
		{Instance: notificationInstance{Name: "test-db", Owner: "bob"}, Kind: "RETAINED", TargetAt: now.Add(6 * 24 * time.Hour)},
		{Instance: notificationInstance{Name: "old-build", Owner: "carol"}, Kind: "RETENTION_END", TargetAt: now.Add(12 * time.Hour)},
	}
	message := notificationMessage(c, items, now)
	for _, want := range []string{"## 🖥️", "**3 台**", "### 1. dev-api", "### 2. test-db", "### 3. old-build", "2026-10-08 20:30:00", "**30 分钟**", "#DC2626", "#D97706", "磁盘将被删除", "path%28x%29/#/my-instances", "<at email=\"alice@example.com\">"} {
		if !strings.Contains(message, want) {
			t.Errorf("缺少消息样式 %q：%s", want, message)
		}
	}
	if strings.Count(message, "超过 7 天的续期") != 1 || strings.Count(message, "**处理提示**") != 1 {
		t.Fatal("处理说明重复")
	}
	for _, bad := range []string{"[点击](https://evil.example)", "**all**", "## header", "`code`", "<at user_id=\"-1\">all</at>"} {
		value := notificationText(bad)
		if strings.ContainsAny(value, "[]()*#`<>") {
			t.Fatalf("Markdown 注入未转义：%s", value)
		}
	}
	testMessage := notificationTestMessage(c)
	if !strings.Contains(testMessage, "不代表任何实例到期") || !strings.Contains(testMessage, "[查看我的虚拟机]") {
		t.Fatal("测试通知缺少安全说明或入口")
	}
}

func TestOrdinaryUserCannotAccessNotificationSettings(t *testing.T) {
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/v1/notifications/config"}, {"PUT", "/api/v1/notifications/config"},
		{"POST", "/api/v1/notifications/test"}, {"GET", "/api/v1/notifications/events"},
	} {
		if ordinaryUserRouteAllowed(httptest.NewRequest(route.method, route.path, nil)) {
			t.Fatalf("普通用户不应访问通知接口：%s", route.path)
		}
	}
}

// 数据库集成验证使用独立随机命名的 schema，只创建测试表，不操作实际虚拟机。
func TestNotificationDatabaseDelivery(t *testing.T) {
	dsn := os.Getenv("VMP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("未设置 VMP_TEST_DATABASE_URL，跳过数据库集成验证")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("notification_test_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE TABLE applications(id uuid PRIMARY KEY,applicant text); CREATE TABLE users(username text,display_name text,email text); CREATE TABLE instances(id uuid PRIMARY KEY,application_id uuid,name text,lifecycle_status text,expires_at timestamptz,retention_until timestamptz,updated_at timestamptz DEFAULT now());`)
	if err != nil {
		t.Fatal(err)
	}
	sql, err := migrations.Files.ReadFile("015_group_notifications.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
	}
	var deliveries atomic.Int32
	var reject atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveries.Add(1)
		if reject.Load() {
			io.WriteString(w, `{"errcode":403}`)
		} else {
			io.WriteString(w, `{"result":"ok"}`)
		}
	}))
	defer server.Close()
	a := &API{Service: &platform.Service{DB: pool}, SettingsEncryptionKey: []byte(strings.Repeat("a", 32))}
	cipher, err := encryptSecret(a.SettingsEncryptionKey, []byte(server.URL+"?key=test"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE notification_settings SET enabled=true,webhook_ciphertext=$1,enabled_since=now()`, cipher); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO applications VALUES('00000000-0000-0000-0000-000000000001','owner'); INSERT INTO instances(id,application_id,name,lifecycle_status,expires_at) VALUES('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001','notification-test','RUNNING',now()+interval '2 hours');`); err != nil {
		t.Fatal(err)
	}
	run := func() {
		t.Helper()
		if err := a.dispatchNotifications(ctx); err != nil {
			t.Fatal(err)
		}
	}
	run()
	run()
	if deliveries.Load() != 1 {
		t.Fatal("同一阶段重复发送")
	}
	if _, err = pool.Exec(ctx, `UPDATE instances SET expires_at=now()+interval '30 minutes'; UPDATE notification_settings SET last_attempt_at=NULL;`); err != nil {
		t.Fatal(err)
	}
	reject.Store(true)
	run()
	var pending int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE status='PENDING' AND attempts=1`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("失败后未进入重试：%d %v", pending, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE instances SET expires_at=now()+interval '48 hours'; UPDATE notification_settings SET last_attempt_at=NULL; UPDATE notification_events SET next_attempt_at=now();`); err != nil {
		t.Fatal(err)
	}
	run()
	if deliveries.Load() != 2 {
		t.Fatal("续期后仍发送旧提醒")
	}
	var cancelled int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE status='CANCELLED'`).Scan(&cancelled); err != nil || cancelled != 1 {
		t.Fatalf("续期后未取消旧提醒：%d %v", cancelled, err)
	}
}
