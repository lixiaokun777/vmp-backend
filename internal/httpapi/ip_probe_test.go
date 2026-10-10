package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vmp-backend/internal/platform"
)

func TestIPProbeHTTPAdministratorIsolationDatabase(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	service := &platform.Service{DB: db}
	api := &API{Service: service}
	handler := api.Handler()
	cookies := map[string]string{}
	for _, user := range []struct {
		name, role string
		first      bool
	}{{"probe-admin", "ADMIN", false}, {"probe-user", "USER", false}, {"probe-first", "ADMIN", true}} {
		var id string
		if err := db.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash,must_change_password) VALUES($1,$2,'LOCAL',crypt('FixtureStrong123!',gen_salt('bf',4)),$3) RETURNING id::text`, user.name, user.role, user.first).Scan(&id); err != nil {
			t.Fatal(err)
		}
		token, err := generateAgentToken()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256([]byte(token))
		if _, err = db.Exec(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2::uuid,now()+interval '1 hour')`, hash[:], id); err != nil {
			t.Fatal(err)
		}
		cookies[user.name] = token
	}
	var host, network, ip string
	runtimeToken, err := generateAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	runtimeHash := sha256.Sum256([]byte(runtimeToken))
	if err = db.QueryRow(ctx, `INSERT INTO hosts(name,agent_mode,status,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb,last_heartbeat_at) VALUES('api-probe-host','kvm','CORDONED',8,8192,100,8,8192,100,now()) RETURNING id::text`).Scan(&host); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO host_credentials(host_id,token_hash) VALUES($1::uuid,$2)`, host, runtimeHash[:]); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `INSERT INTO networks(name,cidr,gateway,bridge) VALUES('api-probe-network','10.99.0.0/24','10.99.0.1','br0') RETURNING id::text`).Scan(&network); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO host_networks(host_id,network_id,bridge,ready) VALUES($1::uuid,$2::uuid,'br0',true)`, host, network); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `INSERT INTO ip_addresses(network_id,address,status) VALUES($1::uuid,'10.99.0.130','QUARANTINED') RETURNING id::text`, network).Scan(&ip); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, user, bearer string, safety bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if user != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookies[user]})
		}
		if safety {
			r.Header.Set("X-VMP-Request", "1")
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	paths := []string{"/api/v1/ip-addresses/" + ip + "/probe", "/api/v1/networks/" + network + "/probe-quarantined"}
	for _, path := range paths {
		for _, user := range []string{"probe-user", "probe-first"} {
			if w := request("POST", path, `{"release_if_free":true}`, user, "", true); w.Code != 403 {
				t.Fatalf("%s越权复核：%d", user, w.Code)
			}
		}
		if w := request("POST", path, `{"release_if_free":true}`, "probe-admin", "", false); w.Code != 403 {
			t.Fatal("缺少CSRF头仍能排队")
		}
		if w := request("POST", path, `{}`, "", "", true); w.Code != 401 {
			t.Fatal("未登录可探测")
		}
	}
	var jobs int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM tasks`).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("被拒的请求仍写入任务")
	}
	if w := request("POST", paths[1], `{"limit":65}`, "probe-admin", "", true); w.Code != 422 {
		t.Fatal("批量上限未生效")
	}
	w := request("POST", paths[0], `{"release_if_free":true}`, "probe-admin", "", true)
	if w.Code != 202 {
		t.Fatalf("管理员复核不能异步排队：%d", w.Code)
	}
	var queued struct {
		TaskID  string `json:"task_id"`
		Pending bool   `json:"probe_pending"`
	}
	if json.Unmarshal(w.Body.Bytes(), &queued) != nil || queued.TaskID == "" || !queued.Pending {
		t.Fatal("排队响应缺少可观测任务")
	}
	w = request("GET", "/api/v1/ip-addresses?network_id="+network, "", "probe-admin", "", false)
	var list struct {
		Items []struct {
			Pending bool   `json:"probe_pending"`
			Status  string `json:"last_probe_status"`
			HostID  string `json:"last_probe_host_id"`
		} `json:"items"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Items) != 1 || !list.Items[0].Pending || list.Items[0].Status != "PENDING" || list.Items[0].HostID != host {
		t.Fatal("分页IP响应缺探测进度/宿主")
	}
	task, err := service.PollTask(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	wrongResult := platform.TaskResult{ClaimToken: task["claim_token"].(string), Success: true, IPAddress: "10.99.0.131", IPProbeStatus: "FREE", IPProbeMessage: "错误目标"}
	raw, _ := json.Marshal(wrongResult)
	if w = request("POST", "/api/v1/agents/00000000-0000-4000-8000-000000000099/tasks/"+queued.TaskID+"/result", string(raw), "", runtimeToken, false); w.Code != 401 {
		t.Fatal("跨宿主回调可执行")
	}
	if w = request("POST", "/api/v1/agents/"+host+"/tasks/"+queued.TaskID+"/result", string(raw), "", runtimeToken, false); w.Code != 200 {
		t.Fatalf("真实身份错误目标回调未收口：%d", w.Code)
	}
	var state, last string
	if err = db.QueryRow(ctx, `SELECT status,last_probe_status FROM ip_addresses WHERE id=$1::uuid`, ip).Scan(&state, &last); err != nil || state != "QUARANTINED" || last != "ERROR" {
		t.Fatal("错目标仍释放IP", err)
	}
	if w = request("POST", "/api/v1/ip-addresses/"+strings.ToUpper(ip)+"/probe", `{"release_if_free":true}`, "probe-admin", "", true); w.Code != 202 {
		t.Fatal("失败后无法重新复核")
	}
	task, err = service.PollTask(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	valid := platform.TaskResult{ClaimToken: task["claim_token"].(string), Success: true, IPAddress: "10.99.0.130", IPProbeStatus: "FREE", IPProbeMessage: "ARP无响应且探测正常"}
	raw, _ = json.Marshal(valid)
	if w = request("POST", "/api/v1/agents/"+host+"/tasks/"+task["id"].(string)+"/result", string(raw), "", runtimeToken, false); w.Code != 200 {
		t.Fatal("FREE回调失败")
	}
	if err = db.QueryRow(ctx, `SELECT status FROM ip_addresses WHERE id=$1::uuid`, ip).Scan(&state); err != nil || state != "FREE" {
		t.Fatal("确认空闲后没有安全解除")
	}
}
