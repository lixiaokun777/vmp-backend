package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"vmp-backend/internal/platform"
)

// 通过真实 PostgreSQL 和完整鉴权 Handler 读取详情，覆盖 UUID 与 JSON 文本混用的 SQL 回归。
func TestInstanceDetailHTTPDatabase(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	api := &API{Service: &platform.Service{DB: db}}
	handler := api.Handler()
	cookies := map[string]string{}
	for _, user := range []struct{ name, role string }{{"detail-admin", "ADMIN"}, {"detail-alice", "USER"}, {"detail-bob", "USER"}} {
		var id string
		if err := db.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash) VALUES($1,$2,'LOCAL',crypt('FixtureStrong123!',gen_salt('bf',4))) RETURNING id::text`, user.name, user.role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		cookie, err := generateAgentToken()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256([]byte(cookie))
		if _, err := db.Exec(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2::uuid,now()+interval '1 hour')`, hash[:], id); err != nil {
			t.Fatal(err)
		}
		cookies[user.name] = cookie
	}
	var host, network, probeIP string
	if err := db.QueryRow(ctx, `INSERT INTO hosts(name,agent_mode,status,management_ip,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb,quota_cpu,quota_memory_mb,quota_disk_gb,reserved_cpu,reserved_memory_mb,reserved_disk_gb) VALUES('detail-host','kvm','ACTIVE','192.0.2.41',8,16384,500,8,16384,500,8,16384,500,3,6144,120) RETURNING id::text`).Scan(&host); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO networks(name,cidr,gateway,bridge) VALUES('detail-network','10.89.0.0/24','10.89.0.1','br0') RETURNING id::text`).Scan(&network); err != nil {
		t.Fatal(err)
	}
	const privateImagePath = "/fixture/private/detail-template.qcow2"
	if _, err := db.Exec(ctx, `INSERT INTO images(id,name,os_family,version,file_name,source_type,source_location,sync_status,enabled) VALUES('detail-image','详情测试镜像','ubuntu','22.04','detail-template.qcow2','local',$1,'READY',true)`, privateImagePath); err != nil {
		t.Fatal(err)
	}
	const aliceInstance = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const bobInstance = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	for _, instance := range []struct {
		id, name, owner, flavor, address string
		cpu, memory, disk                int
	}{
		{aliceInstance, "detail-alice-vm", "detail-alice", "c2m4", "10.89.0.130", 2, 4096, 80},
		{bobInstance, "detail-bob-vm", "detail-bob", "c1m2", "10.89.0.131", 1, 2048, 40},
	} {
		var application string
		if err := db.QueryRow(ctx, `INSERT INTO applications(request_no,applicant,instance_name,purpose,flavor_id,image_id,lease_hours,status) VALUES($1,$2,$3,'详情HTTP回归',$4,'detail-image',24,'APPROVED') RETURNING id::text`, "REQ-"+instance.name, instance.owner, instance.name, instance.flavor).Scan(&application); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO instances(id,application_id,host_id,name,lifecycle_status,provider_status,ip_address,expires_at,allocated_cpu,allocated_memory_mb,allocated_disk_gb,flavor_name_snapshot,network_id,delivery_status) VALUES($1::uuid,$2::uuid,$3::uuid,$4,'RUNNING','RUNNING',$5::inet,now()+interval '1 day',$6,$7,$8,'实例分配时规格',$9::uuid,'READY')`, instance.id, application, host, instance.name, instance.address, instance.cpu, instance.memory, instance.disk, network); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO ip_addresses(network_id,address,status,instance_id,allocated_at) VALUES($1::uuid,$2::inet,'ALLOCATED',$3::uuid,now())`, network, instance.address, instance.id); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.QueryRow(ctx, `INSERT INTO ip_addresses(network_id,address,status) VALUES($1::uuid,'10.89.0.132','QUARANTINED') RETURNING id::text`, network).Scan(&probeIP); err != nil {
		t.Fatal(err)
	}
	resourceSnapshot := func(t *testing.T) string {
		t.Helper()
		var value string
		// 会话 last_seen_at 的正常更新不是资源变更；实例/IP/配额/任务和申请必须完全不变。
		if err := db.QueryRow(ctx, `SELECT jsonb_build_object('hosts',(SELECT jsonb_agg(to_jsonb(h) ORDER BY h.id) FROM hosts h),'instances',(SELECT jsonb_agg(to_jsonb(i) ORDER BY i.id) FROM instances i),'ips',(SELECT jsonb_agg(to_jsonb(ip) ORDER BY ip.id) FROM ip_addresses ip),'tasks',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM tasks t),'applications',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM applications a))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	get := func(user, instance string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/instances/"+instance, nil)
		if user != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookies[user]})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	type detailResponse struct {
		Instance map[string]any   `json:"instance"`
		Tasks    []map[string]any `json:"tasks"`
		Audits   []map[string]any `json:"audit_logs"`
	}
	decode := func(t *testing.T, w *httptest.ResponseRecorder) detailResponse {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("真实数据库详情接口应返回200，得到%d", w.Code)
		}
		var response detailResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Instance["id"] != aliceInstance || response.Tasks == nil || response.Audits == nil {
			t.Fatal("详情响应不是规范实例对象和任务/审计数组")
		}
		if response.Instance["delivery_status"] != "READY" || response.Instance["resource_snapshot"].(map[string]any)["disk_gb"] != float64(80) {
			t.Fatal("分层交付和分配快照丢失")
		}
		return response
	}
	baseline := resourceSnapshot(t)
	t.Run("未登录和其他用户不能读取", func(t *testing.T) {
		if w := get("", aliceInstance); w.Code != http.StatusUnauthorized {
			t.Fatal("未登录请求没有401")
		}
		if w := get("detail-bob", aliceInstance); w.Code != http.StatusNotFound || bytes.Contains(w.Body.Bytes(), []byte("detail-alice-vm")) {
			t.Fatal("其他用户读取了不属于自己的实例")
		}
	})
	for _, user := range []string{"detail-admin", "detail-alice"} {
		t.Run(user+"无任务审计返回空数组", func(t *testing.T) {
			w := get(user, aliceInstance)
			response := decode(t, w)
			if len(response.Tasks) != 0 || len(response.Audits) != 0 {
				t.Fatal("空详情返回了额外历史")
			}
			var raw map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &raw) != nil || !bytes.Equal(bytes.TrimSpace(raw["tasks"]), []byte("[]")) || !bytes.Equal(bytes.TrimSpace(raw["audit_logs"]), []byte("[]")) {
				t.Fatal("无历史必须返回[]，不能为null或缺字段")
			}
			image := response.Instance["image"].(map[string]any)
			_, visible := image["source_location"]
			if user == "detail-admin" && image["source_location"] != privateImagePath {
				t.Fatal("管理员看不到已登记镜像路径")
			}
			if user != "detail-admin" && (visible || bytes.Contains(w.Body.Bytes(), []byte(privateImagePath))) {
				t.Fatal("普通用户详情泄露了镜像路径")
			}
		})
	}
	if resourceSnapshot(t) != baseline {
		t.Fatal("空详情读取改变了资源账本")
	}
	const hiddenHash = "fixture-detail-password-hash-never-return"
	const hiddenClaim = "fixture-detail-claim-token-never-return"
	createTask := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1"
	probeTask := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2"
	for _, task := range []struct{ id, kind, resource, related string }{
		{createTask, "CREATE_INSTANCE", aliceInstance, ""},
		{probeTask, "PROBE_IP_ADDRESS", probeIP, aliceInstance},
		{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3", "CREATE_INSTANCE", bobInstance, ""},
		{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb4", "PROBE_IP_ADDRESS", probeIP, bobInstance},
		{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb5", "SYNC_IMAGE", host, aliceInstance},
	} {
		payload, err := json.Marshal(map[string]any{"retry_instance_id": task.related, "password_hash": hiddenHash, "ip_address": "10.89.0.132"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO tasks(id,idempotency_key,task_type,resource_id,host_id,status,payload,result,claim_token,attempt) VALUES($1::uuid,'detail:'||$1::uuid::text,$2,$3::uuid,$4::uuid,'SUCCEEDED',$5,$5,$6,1)`, task.id, task.kind, task.resource, host, payload, hiddenClaim); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES('detail-alice','detail.fixture.owner','instance',$1,'{}'),('detail-bob','detail.fixture.other','instance',$2,'{}'),('detail-alice','detail.fixture.other_namespace','ip_address',$1,'{}')`, aliceInstance, bobInstance); err != nil {
		t.Fatal(err)
	}
	baseline = resourceSnapshot(t)
	for _, user := range []string{"detail-admin", "detail-alice"} {
		for _, pathID := range []string{aliceInstance, strings.ToUpper(aliceInstance)} {
			t.Run(user+"关联历史和UUID规范化"+pathID, func(t *testing.T) {
				w := get(user, pathID)
				response := decode(t, w)
				ids := make([]string, 0, len(response.Tasks))
				for _, task := range response.Tasks {
					ids = append(ids, task["id"].(string))
					for _, forbidden := range []string{"payload", "password_hash", "claim_token", "result"} {
						if _, exists := task[forbidden]; exists {
							t.Fatal("任务历史返回了秘密负载字段")
						}
					}
				}
				sort.Strings(ids)
				if len(ids) != 2 || ids[0] != createTask || ids[1] != probeTask {
					t.Fatal("CREATE/关联PROBE遗漏，或混入其他实例和非PROBE任务")
				}
				if len(response.Audits) != 1 || response.Audits[0]["action"] != "detail.fixture.owner" {
					t.Fatal("大小写UUID审计集合不一致或混入其他实例审计")
				}
				if bytes.Contains(w.Body.Bytes(), []byte(hiddenHash)) || bytes.Contains(w.Body.Bytes(), []byte(hiddenClaim)) {
					t.Fatal("详情响应泄露了任务秘密内容")
				}
				if user != "detail-admin" && bytes.Contains(w.Body.Bytes(), []byte(privateImagePath)) {
					t.Fatal("有历史的普通用户详情泄露镜像路径")
				}
				if resourceSnapshot(t) != baseline {
					t.Fatal("详情读取改变了实例、IP、配额、任务或申请")
				}
			})
		}
	}
	if w := get("detail-bob", strings.ToUpper(aliceInstance)); w.Code != http.StatusNotFound {
		t.Fatal("大写UUID绕过了所有者隔离")
	}
	if resourceSnapshot(t) != baseline {
		t.Fatal("被拒的详情读取改变了资源")
	}
}
