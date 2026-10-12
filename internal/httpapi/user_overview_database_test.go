package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vmp-backend/internal/platform"
)

func TestOrdinaryUserOverviewApplicationsAndMetricsAreIsolated(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	api := &API{Service: &platform.Service{DB: db}}
	handler := api.Handler()

	cookies := map[string]string{}
	for _, username := range []string{"overview-alice", "overview-bob"} {
		var userID string
		if err := db.QueryRow(ctx, `INSERT INTO users(username,role,source,password_hash) VALUES($1,'USER','LOCAL',crypt('FixtureStrong123!',gen_salt('bf',4))) RETURNING id::text`, username).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		token := username + "-session-token"
		hash := sha256.Sum256([]byte(token))
		if _, err := db.Exec(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2::uuid,now()+interval '1 hour')`, hash[:], userID); err != nil {
			t.Fatal(err)
		}
		cookies[username] = token
	}
	if _, err := db.Exec(ctx, `UPDATE platform_policy SET max_instances=3,max_cpu=8,max_memory_mb=16384,max_disk_gb=300`); err != nil {
		t.Fatal(err)
	}

	instances := map[string]string{"overview-alice": "aaaaaaaa-1111-4111-8111-111111111111", "overview-bob": "bbbbbbbb-2222-4222-8222-222222222222"}
	for owner, instanceID := range instances {
		var applicationID string
		if err := db.QueryRow(ctx, `INSERT INTO applications(request_no,applicant,instance_name,purpose,flavor_id,image_id,lease_hours,status) VALUES('REQ-'||$1,$1,$1||'-vm','概览隔离验证','c1m2','ubuntu-2204',24,'APPROVED') RETURNING id::text`, owner).Scan(&applicationID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO instances(id,application_id,name,lifecycle_status,expires_at,allocated_cpu,allocated_memory_mb,allocated_disk_gb,flavor_name_snapshot,delivery_status) VALUES($1::uuid,$2::uuid,$3,'RUNNING',now()+interval '12 hours',1,2048,40,'轻量型','READY')`, instanceID, applicationID, owner+"-vm"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO tasks(idempotency_key,task_type,resource_id,status,result,error_message,attempt,max_attempts) VALUES('overview-create','CREATE_INSTANCE',$1::uuid,'FAILED','{"error_code":"IP_ADDRESS_IN_USE"}'::jsonb,'IP 地址冲突',3,3)`, instances["overview-alice"]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO instance_metrics(instance_id,collected_at,cpu_usage_percent,memory_usage_mb,memory_metric_source) VALUES($1::uuid,now()-interval '1 minute',12.5,768,'guest_unused'),($1::uuid,now(),25,896,'guest_unused'),($2::uuid,now(),99,2048,'guest_unused')`, instances["overview-alice"], instances["overview-bob"]); err != nil {
		t.Fatal(err)
	}

	get := func(username, path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookies[username]})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	overview := get("overview-alice", "/api/v1/me/overview")
	if overview.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", overview.Code, overview.Body.String())
	}
	var summary struct {
		ActiveInstances int `json:"active_instances"`
		UsedCPU         int `json:"used_cpu"`
	}
	if err := json.Unmarshal(overview.Body.Bytes(), &summary); err != nil || summary.ActiveInstances != 1 || summary.UsedCPU != 1 {
		t.Fatalf("unexpected overview: %s err=%v", overview.Body.String(), err)
	}

	applications := get("overview-alice", "/api/v1/applications?scope=mine")
	if applications.Code != http.StatusOK || !json.Valid(applications.Body.Bytes()) {
		t.Fatalf("applications status=%d body=%s", applications.Code, applications.Body.String())
	}
	var page struct {
		Total int `json:"total"`
		Items []struct {
			ErrorCode string `json:"error_code"`
		} `json:"items"`
	}
	if err := json.Unmarshal(applications.Body.Bytes(), &page); err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ErrorCode != "IP_ADDRESS_IN_USE" {
		t.Fatalf("unexpected applications: %s err=%v", applications.Body.String(), err)
	}

	metrics := get("overview-alice", "/api/v1/instances/"+instances["overview-alice"]+"/metrics?hours=24")
	if metrics.Code != http.StatusOK {
		t.Fatalf("metrics status=%d body=%s", metrics.Code, metrics.Body.String())
	}
	var metricPage struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(metrics.Body.Bytes(), &metricPage); err != nil || len(metricPage.Items) != 2 {
		t.Fatalf("unexpected metrics: %s err=%v", metrics.Body.String(), err)
	}
	foreign := get("overview-alice", "/api/v1/instances/"+instances["overview-bob"]+"/metrics?hours=24")
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("foreign metrics status=%d body=%s", foreign.Code, foreign.Body.String())
	}
}

func TestHeartbeatStoresManagedInstanceMetrics(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	service := &platform.Service{DB: db}
	var hostID, applicationID string
	if err := db.QueryRow(ctx, `INSERT INTO hosts(name,agent_mode,status,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb,quota_cpu,quota_memory_mb,quota_disk_gb) VALUES('metrics-host','kvm','ACTIVE',8,16384,500,8,16384,500,8,16384,500) RETURNING id::text`).Scan(&hostID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO applications(request_no,applicant,instance_name,purpose,flavor_id,image_id,lease_hours,status) VALUES('REQ-METRICS','metrics-owner','metrics-vm','指标落库','c1m2','ubuntu-2204',24,'APPROVED') RETURNING id::text`).Scan(&applicationID); err != nil {
		t.Fatal(err)
	}
	const instanceID = "cccccccc-3333-4333-8333-333333333333"
	if _, err := db.Exec(ctx, `INSERT INTO instances(id,application_id,host_id,name,lifecycle_status,expires_at,allocated_cpu,allocated_memory_mb,allocated_disk_gb,flavor_name_snapshot) VALUES($1::uuid,$2::uuid,$3::uuid,'metrics-vm','RUNNING',now()+interval '1 day',1,2048,40,'轻量型')`, instanceID, applicationID, hostID); err != nil {
		t.Fatal(err)
	}
	cpu, memory := 37.5, 1024
	measured := time.Now().UTC().Truncate(time.Second)
	err := service.Heartbeat(ctx, hostID, platform.Heartbeat{Status: "ACTIVE", AllocatableCPU: 8, AllocatableMemoryMB: 16384, AllocatableDiskGB: 500, InventoryComplete: true, Facts: platform.HostFacts{BudgetSource: "CONFIGURED_TOTAL", ResourceMeasuredAt: measured, SafeAvailableMemoryMB: 8192, SafeAvailableDiskGB: 400}, Domains: []platform.Domain{{ProviderUUID: instanceID, Name: "metrics-vm", State: "RUNNING", VCPUs: 1, MemoryMB: 2048, Ownership: "MANAGED", PlatformInstanceID: instanceID, CPUUsagePercent: &cpu, MemoryUsageMB: &memory, MemoryMetricSource: "guest_unused"}}})
	if err != nil {
		t.Fatal(err)
	}
	var storedCPU float64
	var storedMemory int
	if err := db.QueryRow(ctx, `SELECT cpu_usage_percent,memory_usage_mb FROM instance_metrics WHERE instance_id=$1::uuid`, instanceID).Scan(&storedCPU, &storedMemory); err != nil || storedCPU != cpu || storedMemory != memory {
		t.Fatalf("stored cpu=%v memory=%v err=%v", storedCPU, storedMemory, err)
	}
}
