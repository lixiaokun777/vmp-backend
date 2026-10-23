package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vmp-backend/internal/platform"
)

func TestSchedulerHTTPAuthorizationAndPreview(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	service := &platform.Service{DB: db}
	api := &API{Service: service}
	handler := api.Handler()
	tokens := map[string]string{}
	for _, role := range []string{"ADMIN", "USER"} {
		var id string
		if err := db.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash) VALUES($1,$2,'LOCAL','fixture') RETURNING id::text`, "scheduler-"+role, role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		token := "scheduler-fixture-" + role
		hash := sha256.Sum256([]byte(token))
		tokens[role] = token
		if _, err := db.Exec(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2::uuid,now()+interval '1 hour')`, hash[:], id); err != nil {
			t.Fatal(err)
		}
	}
	call := func(role, method, path, body string, header bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tokens[role]})
		if header {
			r.Header.Set("X-VMP-Request", "1")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct{ method, path string }{{"GET", "/api/v1/scheduler"}, {"POST", "/api/v1/scheduler/preview"}, {"PUT", "/api/v1/platform-policy"}} {
		if w := call("USER", tc.method, tc.path, `{}`, true); w.Code != 403 {
			t.Fatal("普通用户获得管理员调度权限", tc, w.Code)
		}
	}
	if w := call("ADMIN", "POST", "/api/v1/scheduler/preview", `{}`, false); w.Code != 403 {
		t.Fatal("预览未要求安全请求头", w.Code)
	}
	if w := call("ADMIN", "GET", "/api/v1/scheduler", "", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"sequence":0`) {
		t.Fatal("管理员状态读取失败", w.Code, w.Body.String())
	}
	var network string
	if err := db.QueryRow(ctx, `INSERT INTO networks(name,cidr,gateway,bridge) VALUES('scheduler-preview','10.90.0.0/24','10.90.0.1','br0') RETURNING id::text`).Scan(&network); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"flavor_id":"c1m2","image_id":"ubuntu-2204","network_id":%q,"strategy":"ROUND_ROBIN"}`, network)
	w := call("ADMIN", "POST", "/api/v1/scheduler/preview", body, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"selected_host_id":null`) {
		t.Fatal("无候选宿主预览应明确不可分配", w.Code, w.Body.String())
	}
	for _, body := range []string{`{`, strings.ReplaceAll(body, "ROUND_ROBIN", "SQL_INJECTION"), strings.ReplaceAll(body, network, "not-a-uuid")} {
		if w := call("ADMIN", "POST", "/api/v1/scheduler/preview", body, true); w.Code != 400 && w.Code != 422 {
			t.Fatal("接受无效预览参数", w.Code, w.Body.String())
		}
	}
	p, err := service.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.SchedulingStrategy = platform.ScheduleBalanced
	encoded, _ := json.Marshal(p)
	if w := call("ADMIN", "PUT", "/api/v1/platform-policy", string(encoded), true); w.Code != 200 {
		t.Fatal("策略保存失败", w.Body.String())
	}
	p, err = service.GetPolicy(ctx)
	if err != nil || p.SchedulingStrategy != platform.ScheduleBalanced {
		t.Fatal("策略未持久化", p, err)
	}
	p.SchedulingStrategy = ""
	legacy, _ := json.Marshal(p)
	if w := call("ADMIN", "PUT", "/api/v1/platform-policy", string(legacy), true); w.Code != 200 || !strings.Contains(w.Body.String(), `"scheduling_strategy":"BALANCED"`) {
		t.Fatal("旧客户端响应没有保留当前策略", w.Code, w.Body.String())
	}
	position, err := service.SchedulingStatus(ctx)
	if err != nil || position.Sequence != 0 {
		t.Fatal("预览或保存配置推进了游标", position, err)
	}
}
