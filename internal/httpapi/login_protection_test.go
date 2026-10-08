package httpapi

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"vmp-backend/internal/platform"
	"vmp-backend/migrations"
)

func TestLoginClientIPTrust(t *testing.T) {
	proxies, err := ParseTrustedProxies("172.22.0.3/32,2001:db8::3/128")
	if err != nil {
		t.Fatal(err)
	}
	a := &API{TrustedProxies: proxies}
	for _, tc := range []struct{ peer, header, want string }{
		{"198.51.100.1:1000", "1.2.3.4", "198.51.100.1"},
		{"172.22.0.3:1000", "1.2.3.4, 198.51.100.1", "198.51.100.1"},
		{"172.22.0.3:1000", "198.51.100.1, 172.22.0.3", "198.51.100.1"},
		{"172.22.0.3:1000", "bad", "172.22.0.3"},
		{"[::ffff:198.51.100.1]:1000", "1.2.3.4", "198.51.100.1"},
		{"[2001:db8::3]:1000", "2001:db8::9", "2001:db8::9"},
	} {
		r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", tc.header)
		if got := a.clientIP(r); got != tc.want {
			t.Errorf("%+v 得到 %s", tc, got)
		}
	}
	for _, value := range []string{"garbage", "0.0.0.0/0", "::/0"} {
		if _, err := ParseTrustedProxies(value); err == nil {
			t.Fatalf("接受危险代理配置 %s", value)
		}
	}
	if strings.Contains(loginBucketKey("account", "LOCAL:admin"), "admin") {
		t.Fatal("计数键泄露账号")
	}
}

// 仅操作随机测试命名空间，不修改实际用户、会话或实例。
func TestLoginProtectionDatabase(t *testing.T) {
	dsn := os.Getenv("VMP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("未设置数据库集成验证地址")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("login_test_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	sql, err := migrations.Files.ReadFile("016_login_protection.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
	}
	a := &API{Service: &platform.Service{DB: pool}, SessionTTL: time.Hour}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, retry, err := a.reserveLogin(ctx, "concurrent", 5, 15*time.Minute)
			if err != nil {
				t.Error(err)
				return
			}
			if retry == 0 {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 5 {
		t.Fatalf("并发越限：%d", accepted.Load())
	}
	// 新 API 实例仍共享数据库限制，等同于控制面重启或另一副本。
	other := &API{Service: a.Service}
	if _, retry, err := other.reserveLogin(ctx, "concurrent", 5, 15*time.Minute); err != nil || retry <= 0 {
		t.Fatal("重启绕过限制", err)
	}
	if _, err = pool.Exec(ctx, "UPDATE login_attempt_buckets SET expires_at=now()-interval '1 second' WHERE bucket_key='concurrent'"); err != nil {
		t.Fatal(err)
	}
	token, retry, err := a.reserveLogin(ctx, "concurrent", 5, 15*time.Minute)
	if err != nil || retry != 0 || token.Attempts != 1 {
		t.Fatal("冷却后不能恢复", err)
	}
	a.resetLoginReservation(ctx, token)
	token, _, _ = a.reserveLogin(ctx, "reset", 5, 15*time.Minute)
	_, _, _ = a.reserveLogin(ctx, "reset", 5, 15*time.Minute)
	a.resetLoginReservation(ctx, token)
	var count int
	if err = pool.QueryRow(ctx, "SELECT attempts FROM login_attempt_buckets WHERE bucket_key='reset'").Scan(&count); err != nil || count != 2 {
		t.Fatal("成功抹掉并发失败", err)
	}
	if _, err = pool.Exec(ctx, `CREATE TABLE users(id uuid,username text,display_name text,email text,role text,source text,enabled boolean,must_change_password boolean,ldap_dn text,password_hash text,last_login_at timestamptz,updated_at timestamptz);
 CREATE TABLE user_sessions(token_hash bytea,user_id uuid,expires_at timestamptz,remote_address text,user_agent text);
 CREATE TABLE audit_logs(actor text,action text,resource_type text,resource_id text,detail jsonb,outcome text,source_ip text,user_agent text,request_id text);
 INSERT INTO users VALUES('00000000-0000-0000-0000-000000000001','valid-user','测试用户','','USER','LOCAL',true,false,'',crypt('TestPassword123!',gen_salt('bf',4)),NULL,now());`); err != nil {
		t.Fatal(err)
	}
	login := func(username, password, source, ip, forward string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q,"source":%q}`, username, password, source)))
		r.RemoteAddr = ip + ":1234"
		r.Header.Set("X-Forwarded-For", forward)
		w := httptest.NewRecorder()
		a.authLogin(w, r)
		return w
	}
	// 大小写、空格、换 IP、伪造转发头都不能绕过账号限制。
	for i := 0; i < 6; i++ {
		user := "ghost"
		if i%2 == 1 {
			user = " GHOST "
		}
		w := login(user, "wrong", "LOCAL", fmt.Sprintf("198.51.100.%d", i+1), "1.2.3.4")
		want := 401
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("第 %d 次：%d %s", i+1, w.Code, w.Body.String())
		}
		if i == 5 && w.Header().Get("Retry-After") == "" {
			t.Fatal("没有重试秒数")
		}
	}
	for i := 0; i < 6; i++ {
		w := login("ldap-ghost", "wrong", "LDAP", "198.51.100.20", "")
		want := 401
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("LDAP 限制失败 %d", w.Code)
		}
	}
	// 修改账号名及伪造头不能绕过 IP 总量限制。
	for i := 0; i < 31; i++ {
		w := login(fmt.Sprintf("spray-%d", i), "wrong", "LOCAL", "198.51.100.30", fmt.Sprintf("203.0.113.%d", i))
		want := 401
		if i == 30 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("IP 第 %d 次：%d", i+1, w.Code)
		}
	}
	if w := login("valid-user", "wrong", "LOCAL", "198.51.100.40", ""); w.Code != 401 {
		t.Fatal("错误密码未拒绝")
	}
	w := login("valid-user", "TestPassword123!", "LOCAL", "198.51.100.40", "")
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("正常登录受影响：%d %s", w.Code, w.Body.String())
	}
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM login_attempt_buckets WHERE bucket_key=$1", loginBucketKey("account", "LOCAL:valid-user")).Scan(&count); err != nil || count != 0 {
		t.Fatal("正常登录未清计数", err)
	}
	// 存储不可用时不能继续密码校验。
	pool.Close()
	if w := login("valid-user", "TestPassword123!", "LOCAL", "198.51.100.41", ""); w.Code != 503 {
		t.Fatal("限流存储故障开放登录")
	}
}
