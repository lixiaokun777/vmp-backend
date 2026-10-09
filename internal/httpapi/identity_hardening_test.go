package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"vmp-backend/internal/migrate"
	"vmp-backend/internal/platform"
)

func TestIdentitySecretAndIdentifierPolicy(t *testing.T) {
	for _, value := range []string{"", "dev-bootstrap-token", "change-bootstrap-token", strings.Repeat("a", 64), "change-this-bootstrap-token-with-many-characters"} {
		if ValidateAgentBootstrapSecret(value) == nil {
			t.Fatal("接受了空值、示例或低变化密钥")
		}
	}
	if err := ValidateAgentBootstrapSecret("5c81a02f9d4eb7346a09872d8e170b6349d083ae15fcd67942b0"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"c1m2", "ubuntu-2204", "image.v2_amd64"} {
		if !resourceIdentifierPattern.MatchString(id) {
			t.Fatalf("拒绝合法标识 %s", id)
		}
	}
	for _, id := range []string{"<img src=x onerror=alert(1)>", "bad\"onclick=alert(1)", "../image", "/image", "'quoted'", strings.Repeat("a", 65), "-leading"} {
		if resourceIdentifierPattern.MatchString(id) {
			t.Fatal("接受了不安全资源标识")
		}
	}
	first, err := generateAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateAgentToken()
	if err != nil || first == second || len(first) != 48 || !strings.HasPrefix(first, "vmpa_") {
		t.Fatal("宿主凭据生成不符合独立随机要求")
	}
}

func TestHTTPBodyHasGlobalBound(t *testing.T) {
	handler := withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if _, ok := err.(*http.MaxBytesError); !ok || len(data) > 8<<20 {
			t.Fatal("管理和 Agent 请求体没有总量上限")
		}
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/v1/agents/register", strings.NewReader(strings.Repeat("x", (8<<20)+1))))
}

// 假 LDAP 只在本机响应绑定和查询，不接触真实账号、目录或密码。
func mockLDAP(t *testing.T, usernames []string) (string, func() ([]string, [][]byte)) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var peers []net.Conn
	var bindings []string
	var filters [][]byte
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, peer := range peers {
			peer.Close()
		}
	})
	response := func(id int64, application ber.Tag, result uint64) *ber.Packet {
		packet := ber.NewSequence("响应")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "消息编号"))
		body := ber.Encode(ber.ClassApplication, ber.TypeConstructed, application, nil, "结果")
		body.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, result, "结果码"))
		body.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "匹配 DN"))
		body.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "错误信息"))
		packet.AppendChild(body)
		return packet
	}
	go func() {
		for {
			peer, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			peers = append(peers, peer)
			mu.Unlock()
			go func(peer net.Conn) {
				defer peer.Close()
				page := 0
				for {
					request, err := ber.ReadPacket(peer)
					if err != nil || len(request.Children) < 2 {
						return
					}
					id, _ := request.Children[0].Value.(int64)
					body := request.Children[1]
					switch body.Tag {
					case ldap.ApplicationBindRequest:
						mu.Lock()
						bindings = append(bindings, fmt.Sprint(body.Children[1].Value))
						mu.Unlock()
						peer.Write(response(id, ldap.ApplicationBindResponse, ldap.LDAPResultSuccess).Bytes())
					case ldap.ApplicationSearchRequest:
						mu.Lock()
						filters = append(filters, append([]byte(nil), body.Children[6].Bytes()...))
						mu.Unlock()
						start, end := 0, len(usernames)
						if len(usernames) > 500 {
							start = page * 500
							end = min(len(usernames), start+500)
							page++
						}
						for index, username := range usernames[start:end] {
							packet := ber.NewSequence("目录条目")
							packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "消息编号"))
							entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "用户")
							entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, fmt.Sprintf("uid=%s,ou=%d,dc=test", username, index), "用户 DN"))
							attributes := ber.NewSequence("属性列表")
							attribute := ber.NewSequence("属性")
							attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid", "属性名"))
							values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "值列表")
							values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, username, "用户名"))
							attribute.AppendChild(values)
							attributes.AppendChild(attribute)
							entry.AppendChild(attributes)
							packet.AppendChild(entry)
							if _, err := peer.Write(packet.Bytes()); err != nil {
								return
							}
						}
						done := response(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess)
						if len(usernames) > 500 {
							control := ldap.NewControlPaging(500)
							if end < len(usernames) {
								control.SetCookie([]byte(fmt.Sprint(page)))
							}
							controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "分页控件")
							controls.AppendChild(control.Encode())
							done.AppendChild(controls)
						}
						peer.Write(done.Bytes())
					default:
						return
					}
				}
			}(peer)
		}
	}()
	return "ldap://" + listener.Addr().String(), func() ([]string, [][]byte) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bindings...), append([][]byte(nil), filters...)
	}
}

func TestLDAPLoginFilterAndUniqueDN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
		allowed bool
	}{
		{"唯一匹配", []string{"review"}, true}, {"组规则不匹配", nil, false}, {"重复匹配", []string{"review", "review"}, false}, {"返回其他用户名", []string{"other"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url, captured := mockLDAP(t, tc.entries)
			config := LDAPConfig{URL: url, BindDN: "cn=reader,dc=test", BindPassword: "TemporaryReader123", BaseDN: "dc=test", LoginFilter: "(&(uid=%s)(memberOf=cn=allowed,dc=test))", UsernameAttr: "uid"}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			connection, cleanup, err := openLDAP(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			err = authenticateLDAPConnection(connection, config, "review", "TemporaryUser123")
			if (err == nil) != tc.allowed {
				t.Fatalf("认证结果不符合规则：%v", err)
			}
			bindings, filters := captured()
			expected, _ := ldap.CompileFilter("(&(uid=review)(memberOf=cn=allowed,dc=test))")
			if len(filters) != 1 || !bytes.Equal(filters[0], expected.Bytes()) {
				t.Fatal("未发送真正的登录规则查询")
			}
			if tc.allowed && (len(bindings) != 2 || bindings[1] != "uid=review,ou=0,dc=test") {
				t.Fatal("没有使用新查询的唯一 DN 绑定")
			}
			if !tc.allowed && len(bindings) != 1 {
				t.Fatal("不匹配或歧义用户仍被尝试绑定")
			}
		})
	}
	filter, err := ldapLoginFilter("(uid=%s)", "review*)(uid=admin)")
	if err != nil || filter != "(uid=review\\2a\\29\\28uid=admin\\29)" {
		t.Fatal("用户名未正确转义 LDAP 元字符")
	}
}

func TestLDAPRequestContextDeadline(t *testing.T) {
	for _, startTLS := range []bool{false, true} {
		t.Run(fmt.Sprint(startTLS), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				peer, err := listener.Accept()
				if err == nil {
					accepted <- peer
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			connection, cleanup, err := openLDAP(ctx, LDAPConfig{URL: "ldap://" + listener.Addr().String(), StartTLS: startTLS})
			if err == nil {
				defer cleanup()
				err = connection.Bind("uid=review,dc=test", "TemporaryPassword123")
			}
			if err == nil || time.Since(start) > time.Second {
				t.Fatal("LDAP 无响应时未按上下文期限退出")
			}
			select {
			case peer := <-accepted:
				peer.Close()
			default:
			}
		})
	}
}

func identityTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("VMP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("未设置隔离数据库验证地址")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("identity_test_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close(); admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); admin.Close() })
	if err := migrate.Run(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestScopedAgentIdentityDatabase(t *testing.T) {
	pool := identityTestDatabase(t)
	ctx := context.Background()
	bootstrap := "5c81a02f9d4eb7346a09872d8e170b6349d083ae15fcd67942b0"
	a := &API{Service: &platform.Service{DB: pool}, BootstrapToken: bootstrap}
	handler := a.Handler()
	request := func(method, path, body, token, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
			r.Header.Set("X-VMP-Request", "1")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	register := func(name, token string, first bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/agents/register", strings.NewReader(fmt.Sprintf(`{"name":%q,"mode":"kvm","allocatable_cpu":8,"allocatable_memory_mb":8192,"allocatable_disk_gb":100}`, name)))
		if first {
			r.Header.Set("X-Bootstrap-Token", bootstrap)
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	decodeIdentity := func(w *httptest.ResponseRecorder) (string, string) {
		t.Helper()
		if w.Code != 200 {
			t.Fatalf("身份登记失败，状态 %d", w.Code)
		}
		var body struct {
			ID    string `json:"id"`
			Token string `json:"runtime_token"`
		}
		if json.Unmarshal(w.Body.Bytes(), &body) != nil {
			t.Fatal("身份响应无效")
		}
		return body.ID, body.Token
	}
	hostA, tokenA := decodeIdentity(register("host-a", "", true))
	hostB, tokenB := decodeIdentity(register("host-b", "", true))
	if tokenA == tokenB || tokenA == "" || tokenB == "" {
		t.Fatal("宿主凭据没有隔离")
	}
	if w := request("GET", "/api/v1/agents/"+hostA+"/tasks/next", "", tokenA, ""); w.Code != 204 {
		t.Fatalf("有效独立身份无法领取空任务队列：%d", w.Code)
	}
	if w := request("GET", "/api/v1/agents/"+hostA+"/tasks/next", "", "dev-agent-token", ""); w.Code != 401 {
		t.Fatal("公开旧全局运行令牌仍可认证")
	}
	if register("host-a", "", true).Code != 401 {
		t.Fatal("引导凭据可接管已存在宿主")
	}
	resumedID, resumedToken := decodeIdentity(register("host-a", tokenA, false))
	if resumedID != hostA || resumedToken != "" {
		t.Fatal("续注册身份改变或无故轮换凭据")
	}
	for _, path := range []string{"/heartbeat", "/tasks/next", "/tasks/00000000-0000-0000-0000-000000000001/result", "/tasks/00000000-0000-0000-0000-000000000001/renew", "/console-sessions/test-session/consume"} {
		method := "POST"
		if path == "/tasks/next" {
			method = "GET"
		}
		if w := request(method, "/api/v1/agents/"+hostB+path, `{}`, tokenA, ""); w.Code != 401 {
			t.Fatalf("跨宿主身份获准 %s：%d", path, w.Code)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM host_credentials WHERE octet_length(token_hash)=32`).Scan(&count); err != nil || count != 2 {
		t.Fatal("没有只保存凭据摘要")
	}
	makeSession := func(role string) string {
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash) VALUES($1,$2,'LOCAL',crypt('TemporaryTest123',gen_salt('bf',4))) RETURNING id::text`, strings.ToLower(role), role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		token, _ := generateAgentToken()
		hash := sha256.Sum256([]byte(token))
		if _, err := pool.Exec(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2::uuid,now()+interval '1 hour')`, hash[:], id); err != nil {
			t.Fatal(err)
		}
		return token
	}
	adminCookie, userCookie := makeSession("ADMIN"), makeSession("USER")
	unsafeRequest := httptest.NewRequest("POST", "/api/v1/hosts/"+hostA+"/credentials/rotate", strings.NewReader(`{}`))
	unsafeRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: adminCookie})
	unsafeResponse := httptest.NewRecorder()
	handler.ServeHTTP(unsafeResponse, unsafeRequest)
	if unsafeResponse.Code != 403 {
		t.Fatal("有效管理员 Cookie 不带安全头仍可签发凭据")
	}
	var generationBeforeRotate int
	if err := pool.QueryRow(ctx, `SELECT generation FROM host_credentials WHERE host_id=$1::uuid`, hostA).Scan(&generationBeforeRotate); err != nil || generationBeforeRotate != 1 {
		t.Fatal("安全校验失败的请求仍修改了宿主凭据")
	}
	if w := request("GET", "/api/v1/auth/me", "", "", adminCookie); w.Code != 200 {
		t.Fatal("新增写请求校验错误影响正常读取")
	}
	if request("POST", "/api/v1/hosts/"+hostA+"/credentials/rotate", `{}`, "", userCookie).Code != 403 {
		t.Fatal("普通用户可签发宿主凭据")
	}
	w := request("POST", "/api/v1/hosts/"+hostA+"/credentials/rotate", `{}`, "", adminCookie)
	if w.Code != 200 {
		t.Fatalf("管理员轮换失败：%d", w.Code)
	}
	var rotated struct {
		Token string `json:"runtime_token"`
	}
	json.Unmarshal(w.Body.Bytes(), &rotated)
	if rotated.Token == "" || rotated.Token == tokenA {
		t.Fatal("未签发新凭据")
	}
	if scopedAgentTokenOK(ctx, pool, hostA, tokenA) || !scopedAgentTokenOK(ctx, pool, hostA, rotated.Token) {
		t.Fatal("轮换没有废止旧凭据")
	}
	if w := request("PATCH", "/api/v1/hosts/"+hostA+"/status", `{"status":"ACTIVE"}`, "", adminCookie); w.Code != 422 {
		t.Fatal("没有新 Agent 心跳也能恢复调度")
	}
	heartbeat := `{"status":"ACTIVE","allocatable_cpu":8,"allocatable_memory_mb":8192,"allocatable_disk_gb":100}`
	if w := request("POST", "/api/v1/agents/"+hostA+"/heartbeat", heartbeat, rotated.Token, ""); w.Code != 200 {
		t.Fatalf("轮换后的独立凭据无法上报：%d", w.Code)
	}
	if w := request("PATCH", "/api/v1/hosts/"+hostA+"/status", `{"status":"ACTIVE"}`, "", adminCookie); w.Code != 200 {
		t.Fatal("新 Agent 心跳后无法恢复调度")
	}
	if request("POST", "/api/v1/hosts/"+hostA+"/credentials/revoke", `{}`, "", adminCookie).Code != 200 || scopedAgentTokenOK(ctx, pool, hostA, rotated.Token) {
		t.Fatal("凭据吊销无效")
	}
}

func TestLDAPSyncPreservesPlatformDisableDatabase(t *testing.T) {
	pool := identityTestDatabase(t)
	ctx := context.Background()
	var adminID string
	if err := pool.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash) VALUES('emergency','ADMIN','LOCAL',crypt('FixtureStrong123!',gen_salt('bf',4))) RETURNING id::text`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	adminRequest := func() *http.Request {
		return httptest.NewRequest("POST", "/api/v1/ldap/sync", nil).WithContext(context.WithValue(ctx, authContextKey{}, AuthUser{ID: adminID, Username: "emergency", Role: "ADMIN", Source: "LOCAL"}))
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(username,role,source,ldap_dn,enabled) VALUES('review','ADMIN','LDAP','uid=review,dc=test',false)`); err != nil {
		t.Fatal(err)
	}
	url, _ := mockLDAP(t, []string{"review"})
	a := &API{Service: &platform.Service{DB: pool}, LDAP: LDAPConfig{Active: true, URL: url, BaseDN: "dc=test", LoginFilter: "(uid=%s)", SyncFilter: "(objectClass=person)", UsernameAttr: "uid", DisplayNameAttr: "cn", EmailAttr: "mail"}}
	w := httptest.NewRecorder()
	a.ldapSync(w, adminRequest())
	if w.Code != 200 {
		t.Fatalf("目录同步失败：%d", w.Code)
	}
	var enabled, present bool
	if err := pool.QueryRow(ctx, `SELECT enabled,ldap_directory_present FROM users WHERE username='review'`).Scan(&enabled, &present); err != nil || enabled || !present {
		t.Fatal("同步重新启用了平台停用账号")
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET enabled=true WHERE username='review'`); err != nil {
		t.Fatal(err)
	}
	url, _ = mockLDAP(t, nil)
	a.LDAP.URL = url
	w = httptest.NewRecorder()
	a.ldapSync(w, adminRequest())
	if w.Code != 200 {
		t.Fatalf("空目录同步失败：%d", w.Code)
	}
	if err := pool.QueryRow(ctx, `SELECT enabled,ldap_directory_present FROM users WHERE username='review'`).Scan(&enabled, &present); err != nil || !enabled || present {
		t.Fatal("目录移除与平台停用状态没有分离")
	}
	w = httptest.NewRecorder()
	a.authLogin(w, httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"review","password":"TemporaryUser123","source":"LDAP"}`)))
	if w.Code != 401 {
		t.Fatalf("目录不存在的账号仍能登录：%d", w.Code)
	}
}
