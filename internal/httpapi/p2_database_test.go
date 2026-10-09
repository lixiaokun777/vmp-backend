package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"vmp-backend/internal/platform"
)

func TestServerPaginationAndIsolationDatabase(t *testing.T) {
	pool := identityTestDatabase(t)
	ctx := context.Background()
	a := &API{Service: &platform.Service{DB: pool}}
	cookies := map[string]string{}
	for _, username := range []string{"alice", "bob", "emergency"} {
		role := "USER"
		if username == "emergency" {
			role = "ADMIN"
		}
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash) VALUES($1,$2,'LOCAL',crypt('FixtureStrong123!',gen_salt('bf',4))) RETURNING id::text`, username, role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		cookie, _ := generateAgentToken()
		hash := sha256.Sum256([]byte(cookie))
		if _, err := pool.Exec(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2::uuid,now()+interval '1 hour')`, hash[:], id); err != nil {
			t.Fatal(err)
		}
		cookies[username] = cookie
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(username,role,source,password_hash,enabled) SELECT 'person-'||lpad(n::text,3,'0'),'USER','LOCAL','fixture-only-hash',n>5 FROM generate_series(1,65)n`); err != nil {
		t.Fatal(err)
	}
	var host, network string
	if err := pool.QueryRow(ctx, `INSERT INTO hosts(name,status,agent_mode,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb) VALUES('pagination','ACTIVE','kvm',100,100000,10000,100,100000,10000) RETURNING id::text`).Scan(&host); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO networks(name,cidr,gateway,bridge) VALUES('pages','10.91.0.0/22','10.91.0.1','br0') RETURNING id::text`).Scan(&network); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO ip_addresses(network_id,address) SELECT $1::uuid,'10.91.0.0'::inet+n FROM generate_series(10,909)n`, network); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO applications(request_no,applicant,instance_name,purpose,flavor_id,image_id,lease_hours,status) SELECT 'PAGE-'||n,CASE WHEN n<=25 THEN 'alice' ELSE 'bob' END,'vm-'||lpad(n::text,3,'0'),'分页隔离','c1m2','ubuntu-2204',24,'APPROVED' FROM generate_series(1,50)n`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO instances(application_id,host_id,name,lifecycle_status,expires_at,allocated_cpu,allocated_memory_mb,allocated_disk_gb,flavor_name_snapshot,network_id,delivery_status) SELECT id,$1::uuid,instance_name,'RUNNING',now()+interval '12 hours',1,2048,40,'分页规格',$2::uuid,'READY' FROM applications`, host, network); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE ip_addresses SET status='ALLOCATED',instance_id=(SELECT id FROM instances WHERE name='vm-001'),allocated_at=now() WHERE address='10.91.0.10'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO approval_requests(request_no,request_type,applicant,requested_hours,reason,payload) SELECT 'PAGE-APR-'||n,'CREATE','alice',336,'审批分页',jsonb_build_object('instance_name','approval-'||n) FROM generate_series(1,30)n`); err != nil {
		t.Fatal(err)
	}
	handler := a.Handler()
	get := func(username, path string) map[string]any {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookies[username]})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("分页接口失败%s：%d %s", path, w.Code, w.Body.String())
		}
		var data map[string]any
		if json.Unmarshal(w.Body.Bytes(), &data) != nil {
			t.Fatal("分页JSON无效")
		}
		return data
	}
	users := get("emergency", "/api/v1/users?page=7&page_size=10&keyword=person-&source=LOCAL&role=USER")
	if users["total"] != float64(65) || len(users["items"].([]any)) != 5 {
		t.Fatal("用户没有服务器分页和过滤")
	}
	disabled := get("emergency", "/api/v1/users?status=DISABLED")
	if disabled["total"] != float64(5) {
		t.Fatal("用户状态筛选错误")
	}
	mine := get("alice", "/api/v1/instances?page=3&page_size=10&all=1")
	if mine["total"] != float64(25) || mine["expiring_total"] != float64(25) || len(mine["items"].([]any)) != 5 {
		t.Fatal("实例分页或用户隔离错误")
	}
	filtered := get("alice", "/api/v1/instances?keyword=does-not-exist")
	if filtered["total"] != float64(0) || filtered["expiring_total"] != float64(25) {
		t.Fatal("筛选错误改变了全scope到期提醒统计")
	}
	ips := get("emergency", "/api/v1/ip-addresses?network_id="+network+"&page=6&page_size=100")
	if ips["total"] != float64(900) || len(ips["items"].([]any)) != 100 {
		t.Fatal("IP明细仍被512硬截断")
	}
	allocated := get("emergency", "/api/v1/ip-addresses?network_id="+network+"&status=ALLOCATED")
	row := allocated["items"].([]any)[0].(map[string]any)
	if row["owner"] != "alice" || row["lifecycle_status"] != "RUNNING" {
		t.Fatal("IP缺少服务端归属或生命周期")
	}
	approvals := get("alice", "/api/v1/approvals?type=CREATE&page=3&page_size=10")
	if approvals["total"] != float64(30) || len(approvals["items"].([]any)) != 10 {
		t.Fatal("审批历史分页错误")
	}
	if get("bob", "/api/v1/approvals?scope=all")["total"] != float64(0) {
		t.Fatal("普通用户scope参数泄露其他用户审批")
	}
	clamped := get("emergency", "/api/v1/users?page=999999999&page_size=10&keyword=person-")
	if clamped["page"] != float64(7) {
		t.Fatal("页码越界未正确夹取")
	}
	usage := get("emergency", "/api/v1/flavors?all=1")["items"].([]any)
	for _, item := range usage {
		row := item.(map[string]any)
		if row["id"] == "c1m2" && row["usage"].(map[string]any)["active"] != float64(50) {
			t.Fatal("规格统计使用本页实例而不是全部快照")
		}
	}
}

func TestLastLocalAdministratorRaceDatabase(t *testing.T) {
	pool := identityTestDatabase(t)
	ctx := context.Background()
	a := &API{Service: &platform.Service{DB: pool}}
	ids := []string{}
	for _, name := range []string{"admin-a", "admin-b"} {
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash) VALUES($1,'ADMIN','LOCAL',crypt('FixtureStrong123!',gen_salt('bf',4))) RETURNING id::text`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	var passed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			r := httptest.NewRequest("PATCH", "/api/v1/users/"+ids[1-n], strings.NewReader(`{"role":"USER","enabled":false}`))
			r.SetPathValue("id", ids[1-n])
			r = r.WithContext(context.WithValue(ctx, authContextKey{}, AuthUser{ID: ids[n], Role: "ADMIN"}))
			w := httptest.NewRecorder()
			a.updateUser(w, r)
			if w.Code == 200 {
				passed.Add(1)
			}
		}(n)
	}
	close(start)
	wg.Wait()
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE source='LOCAL' AND role='ADMIN' AND enabled`).Scan(&count); err != nil || count != 1 || passed.Load() != 1 {
		t.Fatal("并发互相停用绕过最后本地管理员保护", err, count, passed.Load())
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET enabled=false`); err != nil {
		t.Fatal(err)
	}
	if err := EnsureBootstrapAdmin(ctx, a, "admin-a", "FixtureStrong123!"); err == nil {
		t.Fatal("初始化自动提升或重新启用了旧账号")
	}
	if err := EnsureBootstrapAdmin(ctx, a, "emergency-new", "FixtureStrong123!"); err != nil {
		t.Fatal("无法初始化新的本地应急管理员", err)
	}
}

func TestLDAPActualPagingDatabase(t *testing.T) {
	pool := identityTestDatabase(t)
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash) VALUES('emergency','ADMIN','LOCAL',crypt('FixtureStrong123!',gen_salt('bf',4))) RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	var names []string
	for n := 0; n < 1001; n++ {
		names = append(names, "directory-"+fmt.Sprint(n))
	}
	url, captured := mockLDAP(t, names)
	a := &API{Service: &platform.Service{DB: pool}, LDAP: LDAPConfig{Active: true, URL: url, BaseDN: "dc=test", LoginFilter: "(uid=%s)", SyncFilter: "(objectClass=person)", UsernameAttr: "uid", DisplayNameAttr: "cn", EmailAttr: "mail"}}
	r := httptest.NewRequest("POST", "/api/v1/ldap/sync", nil).WithContext(context.WithValue(ctx, authContextKey{}, AuthUser{ID: id, Username: "emergency", Role: "ADMIN", Source: "LOCAL"}))
	w := httptest.NewRecorder()
	a.ldapSync(w, r)
	if w.Code != 200 {
		t.Fatalf("真实分页目录同步失败：%d %s", w.Code, w.Body.String())
	}
	_, filters := captured()
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE source='LDAP' AND ldap_directory_present`).Scan(&count); err != nil || count != 1001 || len(filters) != 3 {
		t.Fatal("没有读取所有LDAP页或分页数量不符", err, count, len(filters))
	}
}

func TestDeleteUserUsesQuotaBeforeRowLockDatabase(t *testing.T) {
	pool := identityTestDatabase(t)
	ctx := context.Background()
	a := &API{Service: &platform.Service{DB: pool}}
	var admin, target string
	if err := pool.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash) VALUES('delete-admin','ADMIN','LOCAL',crypt('FixtureStrong123!',gen_salt('bf',4))) RETURNING id::text`).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash) VALUES('delete-target','USER','LOCAL','fixture') RETURNING id::text`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	createTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer createTx.Rollback(ctx)
	if _, err := createTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('user-quota:delete-target',0))`); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		r := httptest.NewRequest("DELETE", "/api/v1/users/"+target, nil)
		r.SetPathValue("id", target)
		r = r.WithContext(context.WithValue(ctx, authContextKey{}, AuthUser{ID: admin, Role: "ADMIN", Source: "LOCAL"}))
		w := httptest.NewRecorder()
		a.deleteUser(w, r)
		done <- w.Code
	}()
	time.Sleep(30 * time.Millisecond)
	probe, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	var name string
	if err := createTx.QueryRow(probe, `SELECT username FROM users WHERE id=$1::uuid FOR SHARE`, target).Scan(&name); err != nil {
		t.Fatal("删除先锁用户行导致创建/额度锁序反转", err)
	}
	if err := createTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 200 {
			t.Fatalf("锁释放后删除失败：%d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("删除与创建锁序死锁")
	}
}
