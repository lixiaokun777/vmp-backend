package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vmp-backend/internal/platform"
)

func governanceRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	return r.WithContext(context.WithValue(r.Context(), authContextKey{}, AuthUser{Username: "isolated-admin", Role: "ADMIN", Source: "LOCAL"}))
}

func TestHistoryArchiveRequiresVerifiedDownloadAndExactIDs(t *testing.T) {
	db := identityTestDatabase(t)
	a := &API{Service: &platform.Service{DB: db}}
	ctx := context.Background()
	if _, err := db.Exec(ctx, `UPDATE platform_policy SET audit_retention_days=180; INSERT INTO audit_logs(actor,action,resource_type,resource_id,created_at) VALUES('old','test','test','old',now()-interval '200 days'),('new','test','test','new',now())`); err != nil {
		t.Fatal(err)
	}
	create := httptest.NewRecorder()
	a.createHistoryArchive(create, governanceRequest("POST", "/api/v1/history/archives", `{"category":"audit"}`))
	if create.Code != 201 {
		t.Fatal(create.Code, create.Body.String())
	}
	var archive struct {
		ID       string `json:"id"`
		Checksum string `json:"checksum"`
		Count    int    `json:"row_count"`
	}
	if json.Unmarshal(create.Body.Bytes(), &archive) != nil || archive.Count != 1 {
		t.Fatal("归档未按保留期限筛选", create.Body.String())
	}
	body := `{"checksum":"` + archive.Checksum + `","confirm":"已下载并校验归档"}`
	purgeRequest := func() *http.Request {
		r := governanceRequest("POST", "/purge", body)
		r.SetPathValue("id", archive.ID)
		return r
	}
	before := httptest.NewRecorder()
	a.purgeHistoryArchive(before, purgeRequest())
	if before.Code != 409 {
		t.Fatal("未下载也允许清理", before.Code)
	}
	download := httptest.NewRecorder()
	r := governanceRequest("GET", "/download", "")
	r.SetPathValue("id", archive.ID)
	a.downloadHistoryArchive(download, r)
	if download.Code != 200 {
		t.Fatal(download.Code, download.Body.String())
	}
	sum := sha256.Sum256(download.Body.Bytes())
	if hex.EncodeToString(sum[:]) != archive.Checksum {
		t.Fatal("压缩归档校验值不符")
	}
	gz, err := gzip.NewReader(bytes.NewReader(download.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(gz)
	gz.Close()
	var archivedRow map[string]any
	if err != nil || json.Unmarshal(bytes.TrimSpace(data), &archivedRow) != nil || archivedRow["actor"] != "old" {
		t.Fatal("归档内容越过期限", err, string(data))
	}
	purge := httptest.NewRecorder()
	a.purgeHistoryArchive(purge, purgeRequest())
	if purge.Code != 200 {
		t.Fatal(purge.Code, purge.Body.String())
	}
	var old, newCount int
	if err = db.QueryRow(ctx, `SELECT count(*) FILTER(WHERE actor='old'),count(*) FILTER(WHERE actor='new') FROM audit_logs`).Scan(&old, &newCount); err != nil || old != 0 || newCount != 1 {
		t.Fatal("清理不是精确旧ID集合", err, old, newCount)
	}
	again := httptest.NewRecorder()
	a.purgeHistoryArchive(again, purgeRequest())
	if again.Code != 409 {
		t.Fatal("重复清理未拒绝")
	}
	var retained int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM history_archives`).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("清理源记录时删除了归档", err)
	}
}

func TestPlatformEventsDeduplicateAndOnlyHostTransitions(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	now := time.Now()
	since := now.Add(-time.Minute)
	if _, err := db.Exec(ctx, `INSERT INTO approval_requests(request_no,request_type,applicant,requested_hours,reason,status) VALUES('isolated-event','CREATE','requester',336,'test','PENDING'); INSERT INTO hosts(name,status,agent_mode,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb,last_heartbeat_at) VALUES('real-isolated','ACTIVE','kvm',8,8192,100,8,8192,100,now()),('mock-isolated','ACTIVE','mock',8,8192,100,8,8192,100,now()-interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	c := notificationSettings{EnabledSince: &since, NotifyApprovals: true, NotifyFailures: true, NotifyHostAlerts: true}
	collect := func() {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err = collectPlatformEvents(ctx, tx, c); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	collect()
	collect()
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM platform_notification_outbox`).Scan(&count); err != nil || count != 1 {
		t.Fatal("审批重复通知或健康/Mock心跳刷屏", err, count)
	}
	if _, err := db.Exec(ctx, `UPDATE hosts SET last_heartbeat_at=now()-interval '3 minutes' WHERE name='real-isolated'`); err != nil {
		t.Fatal(err)
	}
	collect()
	collect()
	if err := db.QueryRow(ctx, `SELECT count(*) FROM platform_notification_outbox WHERE kind='HOST_OFFLINE'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("宿主离线事件未按边沿去重", err, count)
	}
	if _, err := db.Exec(ctx, `UPDATE hosts SET last_heartbeat_at=now() WHERE name='real-isolated'`); err != nil {
		t.Fatal(err)
	}
	collect()
	collect()
	if err := db.QueryRow(ctx, `SELECT count(*) FROM platform_notification_outbox WHERE kind='HOST_RECOVERED'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("宿主恢复重复发送", err, count)
	}
}

func TestGovernanceRoutesRemainAdministratorOnly(t *testing.T) {
	db := identityTestDatabase(t)
	a := &API{Service: &platform.Service{DB: db}}
	ctx := context.Background()
	var uid string
	if err := db.QueryRow(ctx, `INSERT INTO users(username,password_hash) VALUES('ordinary-governance','hash') RETURNING id::text`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	token := "isolated-governance-session"
	sum := sha256.Sum256([]byte(token))
	if _, err := db.Exec(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2::uuid,now()+interval '1 hour')`, sum[:], uid); err != nil {
		t.Fatal(err)
	}
	handler := a.Handler()
	for _, path := range []string{"/api/v1/platform-policy", "/api/v1/approval-delegation", "/api/v1/history/archives"} {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("普通用户可访问管理员治理API", path, w.Code)
		}
	}
}

func TestArchiveChangedRowsAndNewPermanentPolicyAreProtected(t *testing.T) {
	db := identityTestDatabase(t)
	a := &API{Service: &platform.Service{DB: db}}
	ctx := context.Background()
	if _, err := db.Exec(ctx, `UPDATE platform_policy SET audit_retention_days=180; INSERT INTO audit_logs(actor,action,resource_type,resource_id,created_at) VALUES('changed','test','test','changed',now()-interval '200 days')`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.createHistoryArchive(w, governanceRequest("POST", "/archive", `{"category":"audit"}`))
	var archived struct{ ID, Checksum string }
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &archived) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	r := governanceRequest("GET", "/download", "")
	r.SetPathValue("id", archived.ID)
	a.downloadHistoryArchive(httptest.NewRecorder(), r)
	if _, err := db.Exec(ctx, `UPDATE audit_logs SET detail='{"corrected":true}' WHERE actor='changed'; UPDATE platform_policy SET audit_retention_days=0`); err != nil {
		t.Fatal(err)
	}
	purge := func() *httptest.ResponseRecorder {
		r := governanceRequest("POST", "/purge", `{"checksum":"`+archived.Checksum+`","confirm":"已下载并校验归档"}`)
		r.SetPathValue("id", archived.ID)
		w := httptest.NewRecorder()
		a.purgeHistoryArchive(w, r)
		return w
	}
	if w = purge(); w.Code != 422 {
		t.Fatal("旧归档绕过了新的永久保留策略", w.Code, w.Body.String())
	}
	if _, err := db.Exec(ctx, `UPDATE platform_policy SET audit_retention_days=180`); err != nil {
		t.Fatal(err)
	}
	if w = purge(); w.Code != 200 || !strings.Contains(w.Body.String(), `"deleted_count":0`) {
		t.Fatal("归档后改动的记录被清理", w.Code, w.Body.String())
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE actor='changed'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("改动记录未保留", err, n)
	}
}

func TestNotificationArchiveExcludesPendingDelivery(t *testing.T) {
	db := identityTestDatabase(t)
	a := &API{Service: &platform.Service{DB: db}}
	ctx := context.Background()
	if _, err := db.Exec(ctx, `UPDATE platform_policy SET notification_retention_days=30;
		WITH pending AS (INSERT INTO platform_notification_outbox(event_key,kind,resource_id,title,detail,created_at) VALUES('archive-pending','TEST','test','test','test',now()-interval '40 days') RETURNING id)
		INSERT INTO notification_events(instance_id,kind,target_at,status,created_at) SELECT id,'TEST',now(),'FAILED',now()-interval '40 days' FROM pending;
		INSERT INTO notification_events(kind,target_at,status,created_at) VALUES('TEST-FINISHED',now(),'SENT',now()-interval '40 days')`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.createHistoryArchive(w, governanceRequest("POST", "/archive", `{"category":"notifications"}`))
	var archived struct {
		ID, Checksum string
		Count        int `json:"row_count"`
	}
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &archived) != nil || archived.Count != 1 {
		t.Fatal("归档包括了待发送队列", w.Code, w.Body.String())
	}
	r := governanceRequest("GET", "/download", "")
	r.SetPathValue("id", archived.ID)
	a.downloadHistoryArchive(httptest.NewRecorder(), r)
	r = governanceRequest("POST", "/purge", `{"checksum":"`+archived.Checksum+`","confirm":"已下载并校验归档"}`)
	r.SetPathValue("id", archived.ID)
	w = httptest.NewRecorder()
	a.purgeHistoryArchive(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var pending, events int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM platform_notification_outbox WHERE status='PENDING'),(SELECT count(*) FROM notification_events)`).Scan(&pending, &events); err != nil || pending != 1 || events != 1 {
		t.Fatal("清理误删待发送事件", err, pending, events)
	}
}
