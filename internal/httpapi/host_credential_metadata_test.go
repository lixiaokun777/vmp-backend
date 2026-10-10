package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vmp-backend/internal/platform"
)

// 页面只获得凭据元数据；签发、轮换和吊销不得改变已有实例、IP 或资源预算。
func TestHostCredentialManagementMetadataDatabase(t *testing.T) {
	pool := identityTestDatabase(t)
	ctx := context.Background()
	a := &API{Service: &platform.Service{DB: pool}}
	handler := a.Handler()
	makeSession := func(username, role string, mustChange, enabled bool) string {
		t.Helper()
		var userID string
		if err := pool.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash,must_change_password,enabled) VALUES($1,$2,'LOCAL',crypt('FixtureStrong123!',gen_salt('bf',4)),$3,$4) RETURNING id::text`, username, role, mustChange, enabled).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		token, err := generateAgentToken()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256([]byte(token))
		if _, err := pool.Exec(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2::uuid,now()+interval '1 hour')`, hash[:], userID); err != nil {
			t.Fatal(err)
		}
		return token
	}
	admin := makeSession("credential-admin", "ADMIN", false, true)
	ordinary := makeSession("credential-user", "USER", false, true)
	firstLogin := makeSession("credential-first-login", "ADMIN", true, true)
	disabled := makeSession("credential-disabled", "ADMIN", false, false)
	request := func(method, path, cookie, bearer string, safetyHeader bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if safetyHeader {
			r.Header.Set("X-VMP-Request", "1")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	var hostID, networkID, applicationID, instanceID string
	if err := pool.QueryRow(ctx, `INSERT INTO hosts(name,status,agent_mode,management_ip,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb,reserved_cpu,reserved_memory_mb,reserved_disk_gb) VALUES('credential-existing-host','ACTIVE','kvm','192.0.2.21',8,8192,100,8,8192,100,2,4096,40) RETURNING id::text`).Scan(&hostID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO networks(name,cidr,gateway,bridge) VALUES('credential-network','10.99.0.0/24','10.99.0.1','br0') RETURNING id::text`).Scan(&networkID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO applications(request_no,applicant,instance_name,purpose,flavor_id,image_id,lease_hours,status) VALUES('CREDENTIAL-VM','credential-user','credential-existing-vm','凭据回归测试','c2m4','ubuntu-2204',24,'APPROVED') RETURNING id::text`).Scan(&applicationID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO instances(application_id,host_id,name,lifecycle_status,provider_status,ip_address,expires_at,allocated_cpu,allocated_memory_mb,allocated_disk_gb,flavor_name_snapshot,network_id,delivery_status) VALUES($1::uuid,$2::uuid,'credential-existing-vm','RUNNING','RUNNING','10.99.0.130',now()+interval '1 day',2,4096,40,'原分配规格',$3::uuid,'READY') RETURNING id::text`, applicationID, hostID, networkID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO ip_addresses(network_id,address,status,instance_id,allocated_at) VALUES($1::uuid,'10.99.0.130','ALLOCATED',$2::uuid,now())`, networkID, instanceID); err != nil {
		t.Fatal(err)
	}
	resourceSnapshot := func() string {
		t.Helper()
		var snapshot string
		if err := pool.QueryRow(ctx, `SELECT jsonb_build_object('host',(SELECT to_jsonb(h)-'status'-'updated_at' FROM hosts h WHERE h.id=$1::uuid),'instance',(SELECT to_jsonb(i) FROM instances i WHERE i.id=$2::uuid),'application',(SELECT to_jsonb(ap) FROM applications ap WHERE ap.id=$3::uuid),'addresses',(SELECT jsonb_agg(to_jsonb(ip) ORDER BY ip.address) FROM ip_addresses ip WHERE ip.instance_id=$2::uuid),'tasks',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM tasks t WHERE t.host_id=$1::uuid))::text`, hostID, instanceID, applicationID).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	baseline := resourceSnapshot()
	checkResources := func() {
		t.Helper()
		if resourceSnapshot() != baseline {
			t.Fatal("凭据操作改变了宿主身份、已有虚拟机、IP、任务或资源预算")
		}
	}
	checkMetadata := func(status string, generation int64, secret string) {
		t.Helper()
		w := request("GET", "/api/v1/hosts", admin, "", false)
		if w.Code != http.StatusOK {
			t.Fatalf("管理员读取凭据状态失败：%d", w.Code)
		}
		var response struct {
			Items []struct {
				ID         string     `json:"id"`
				Name       string     `json:"name"`
				Status     string     `json:"credential_status"`
				Generation int64      `json:"credential_generation"`
				UpdatedAt  *time.Time `json:"credential_updated_at"`
			} `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Items) != 1 {
			t.Fatal("凭据列表响应结构无效")
		}
		item := response.Items[0]
		if item.ID != hostID || item.Name != "credential-existing-host" || item.Status != status || item.Generation != generation {
			t.Fatal("凭据状态或代次与原宿主不符")
		}
		if status == "MISSING" {
			if item.UpdatedAt != nil || !strings.Contains(w.Body.String(), `"credential_updated_at":null`) {
				t.Fatal("未签发凭据的更新时间必须为 null")
			}
		} else {
			var expected time.Time
			var hash string
			if err := pool.QueryRow(ctx, `SELECT updated_at,encode(token_hash,'hex') FROM host_credentials WHERE host_id=$1::uuid`, hostID).Scan(&expected, &hash); err != nil {
				t.Fatal(err)
			}
			if item.UpdatedAt == nil || !item.UpdatedAt.Equal(expected) {
				t.Fatal("凭据列表更新时间与数据库不符")
			}
			if strings.Contains(w.Body.String(), hash) {
				t.Fatal("凭据列表泄露了运行令牌摘要")
			}
		}
		for _, forbidden := range []string{`"token_hash"`, `"runtime_token"`} {
			if strings.Contains(w.Body.String(), forbidden) {
				t.Fatal("凭据列表返回了秘密字段")
			}
		}
		if secret != "" && strings.Contains(w.Body.String(), secret) {
			t.Fatal("凭据列表返回了明文运行令牌")
		}
		checkResources()
	}
	checkMetadata("MISSING", 0, "")
	for _, test := range []struct {
		name, cookie string
		want         int
	}{
		{"未登录", "", http.StatusUnauthorized},
		{"普通用户", ordinary, http.StatusForbidden},
		{"未完成首登改密", firstLogin, http.StatusForbidden},
		{"已停用管理员", disabled, http.StatusUnauthorized},
	} {
		for _, action := range []struct{ method, path string }{{"GET", "/api/v1/hosts"}, {"POST", "/api/v1/hosts/" + hostID + "/credentials/rotate"}, {"POST", "/api/v1/hosts/" + hostID + "/credentials/revoke"}} {
			if w := request(action.method, action.path, test.cookie, "", true); w.Code != test.want {
				t.Fatalf("%s未被权限边界拒绝：%s %d", test.name, action.path, w.Code)
			}
		}
	}
	for _, action := range []string{"rotate", "revoke"} {
		if w := request("POST", "/api/v1/hosts/"+hostID+"/credentials/"+action, admin, "", false); w.Code != http.StatusForbidden {
			t.Fatal("缺少安全请求头仍能变更凭据")
		}
	}
	checkMetadata("MISSING", 0, "")
	rotate := func(expectedGeneration int64) string {
		t.Helper()
		w := request("POST", "/api/v1/hosts/"+hostID+"/credentials/rotate", admin, "", true)
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("管理员签发失败或响应允许缓存：%d", w.Code)
		}
		var result struct {
			HostID     string `json:"host_id"`
			Name       string `json:"name"`
			Token      string `json:"runtime_token"`
			Generation int64  `json:"generation"`
			Status     string `json:"status"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.HostID != hostID || result.Name != "credential-existing-host" || result.Generation != expectedGeneration || result.Status != "CORDONED" || !scopedAgentTokenOK(ctx, pool, hostID, result.Token) {
			t.Fatal("签发响应改变宿主身份或凭据无效")
		}
		checkMetadata("ACTIVE", expectedGeneration, result.Token)
		return result.Token
	}
	firstToken := rotate(1)
	secondToken := rotate(2)
	if firstToken == secondToken || scopedAgentTokenOK(ctx, pool, hostID, firstToken) {
		t.Fatal("再次签发未立即废止原凭据")
	}
	if w := request("GET", "/api/v1/agents/"+hostID+"/catalog", "", firstToken, false); w.Code != http.StatusUnauthorized {
		t.Fatal("重新签发后旧凭据仍可访问 Agent 接口")
	}
	if w := request("GET", "/api/v1/agents/"+hostID+"/catalog", "", secondToken, false); w.Code != http.StatusOK {
		t.Fatal("新凭据不能访问原宿主 Agent 接口")
	}
	if w := request("POST", "/api/v1/hosts/"+hostID+"/credentials/revoke", admin, "", true); w.Code != http.StatusOK {
		t.Fatalf("吊销失败：%d", w.Code)
	}
	checkMetadata("REVOKED", 2, secondToken)
	if scopedAgentTokenOK(ctx, pool, hostID, secondToken) {
		t.Fatal("吊销状态仍可认证")
	}
	thirdToken := rotate(3)
	if thirdToken == secondToken || scopedAgentTokenOK(ctx, pool, hostID, secondToken) {
		t.Fatal("吊销后重新签发未使用独立新凭据")
	}
	if w := request("POST", "/api/v1/hosts/00000000-0000-4000-8000-000000000099/credentials/rotate", admin, "", true); w.Code != http.StatusNotFound {
		t.Fatal("不存在的宿主被创建为新身份")
	}
	checkMetadata("ACTIVE", 3, thirdToken)
}
