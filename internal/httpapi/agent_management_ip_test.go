package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"vmp-backend/internal/platform"
)

func TestScopedAgentResumePreservesManagementIPDatabase(t *testing.T) {
	pool := identityTestDatabase(t)
	ctx := context.Background()
	bootstrap := "5c81a02f9d4eb7346a09872d8e170b6349d083ae15fcd67942b0"
	a := &API{Service: &platform.Service{DB: pool}, BootstrapToken: bootstrap}
	handler := a.Handler()
	call := func(body map[string]any, token string, first bool) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/api/v1/agents/register", strings.NewReader(string(raw)))
		r.RemoteAddr = "192.0.2.99:1000"
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
	body := map[string]any{"name": "node-ip-fixture", "mode": "kvm", "management_ip": "10.200.8.172", "allocatable_cpu": 8, "allocatable_memory_mb": 8192, "allocatable_disk_gb": 100}
	w := call(body, "", true)
	if w.Code != 200 {
		t.Fatalf("首次纳管失败：%d", w.Code)
	}
	var registration struct {
		ID    string `json:"id"`
		Token string `json:"runtime_token"`
	}
	if json.Unmarshal(w.Body.Bytes(), &registration) != nil {
		t.Fatal("纳管响应无效")
	}
	check := func(address string, cpu int) {
		t.Helper()
		var saved string
		var actualCPU int
		if err := pool.QueryRow(ctx, `SELECT host(management_ip),agent_allocatable_cpu FROM hosts WHERE id=$1::uuid`, registration.ID).Scan(&saved, &actualCPU); err != nil || saved != address || actualCPU != cpu {
			t.Fatalf("地址或预算不符合预期：%s/%d，错误%v", saved, actualCPU, err)
		}
	}
	check("10.200.8.172", 8)
	for _, variant := range []string{"omitted", "", "   "} {
		delete(body, "management_ip")
		if variant != "omitted" {
			body["management_ip"] = variant
		}
		body["host_id"] = registration.ID
		body["allocatable_cpu"] = 12
		if w := call(body, registration.Token, false); w.Code != 200 {
			t.Fatalf("省略/空地址续注册失败：%d", w.Code)
		}
		check("10.200.8.172", 12)
	}
	body["management_ip"] = "10.200.8.173"
	body["allocatable_cpu"] = 16
	if w := call(body, registration.Token, false); w.Code != 200 {
		t.Fatalf("合法地址更新失败：%d", w.Code)
	}
	check("10.200.8.173", 16)
	for _, invalid := range []string{"not-an-ip", "10.200.8.172/24", "fe80::1%eth0"} {
		body["management_ip"] = invalid
		body["allocatable_cpu"] = 20
		if w := call(body, registration.Token, false); w.Code != 422 {
			t.Fatalf("非法地址没有拒绝：%d", w.Code)
		}
		check("10.200.8.173", 16)
	}
	body["management_ip"] = "10.200.8.174"
	if w := call(body, "", true); w.Code != 401 {
		t.Fatal("引导令牌可修改已纳管地址")
	}
	check("10.200.8.173", 16)
}
