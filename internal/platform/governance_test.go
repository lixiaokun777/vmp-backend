package platform

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestGovernancePolicyDefaultsAndBounds(t *testing.T) {
	p := GovernancePolicy{AutoRenewHours: 24, AutoRenewMaxCount: 3}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []GovernancePolicy{{AutoRenewHours: 169, AutoRenewMaxCount: 3}, {AutoRenewHours: 24, AutoRenewMaxCount: 101}, {AutoRenewHours: 24, AutoRenewMaxCount: 3, AuditRetentionDays: 179}, {AutoRenewHours: 24, AutoRenewMaxCount: 3, NotificationRetentionDays: 29}, {AutoRenewHours: 24, AutoRenewMaxCount: 3, ApprovalRetentionDays: 89}, {AutoRenewHours: 24, AutoRenewMaxCount: 3, MaxCPU: -1}, {AutoRenewHours: 24, AutoRenewMaxCount: 3, MaxFutureLeaseHours: 100000000}} {
		if invalid.Validate() == nil {
			t.Fatal("接受了无效治理策略")
		}
	}
}

func TestUserQuotaConcurrentCreates(t *testing.T) {
	s, _, network := reliabilityFixture(t)
	ctx := context.Background()
	p, err := s.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.MaxInstances = 1
	if err = s.SavePolicy(ctx, "admin", p); err != nil {
		t.Fatal(err)
	}
	var passed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, name := range []string{"quota-first", "quota-second"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			<-start
			if _, err := s.CreateApplication(ctx, "isolated-user", CreateApplicationInput{InstanceName: name, Purpose: "配额并发隔离测试", FlavorID: "c1m2", ImageID: "ubuntu-2204", NetworkID: network, LeaseHours: 1}); err == nil {
				passed.Add(1)
			} else {
				t.Logf("申请被拒绝：%v", err)
			}
		}(name)
	}
	close(start)
	wg.Wait()
	if passed.Load() != 1 {
		t.Fatalf("并发申请成功 %d 次，期望仅 1", passed.Load())
	}
	var count int
	if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM instances`).Scan(&count); err != nil || count != 1 {
		t.Fatal("配额检查与创建未原子化", err, count)
	}
}

func TestAutoRenewBoundAndToggleCannotResetCount(t *testing.T) {
	s, host, network := reliabilityFixture(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(ctx, `INSERT INTO users(username,password_hash) VALUES('isolated-user',crypt('Isolated-Test-2026',gen_salt('bf'))) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	id := reliabilityInstance(t, s, host, network, "auto-renew-isolated", true)
	p, err := s.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.AutoRenewEnabled = true
	p.AutoRenewMaxCount = 1
	if err = s.SavePolicy(ctx, "admin", p); err != nil {
		t.Fatal(err)
	}
	if err = s.SetAutoRenew(ctx, "someone-else", false, id, true, 24, 1); err == nil {
		t.Fatal("越权配置自动续期")
	}
	if err = s.SetAutoRenew(ctx, "isolated-user", false, id, true, 24, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, `UPDATE instances SET expires_at=now()+interval '30 minutes' WHERE id=$1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	if err = s.RunAutoRenew(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	var enabled bool
	if err = s.DB.QueryRow(ctx, `SELECT renewed_count,enabled FROM instance_auto_renew WHERE instance_id=$1::uuid`, id).Scan(&count, &enabled); err != nil || count != 1 {
		t.Fatal("自动续期未执行", err, count)
	}
	if err = s.SetAutoRenew(ctx, "isolated-user", false, id, false, 24, 1); err != nil {
		t.Fatal(err)
	}
	if err = s.SetAutoRenew(ctx, "isolated-user", false, id, true, 24, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, `UPDATE instances SET expires_at=now()+interval '30 minutes' WHERE id=$1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	if err = s.RunAutoRenew(ctx); err != nil {
		t.Fatal(err)
	}
	var message string
	if err = s.DB.QueryRow(ctx, `SELECT renewed_count,enabled,last_error FROM instance_auto_renew WHERE instance_id=$1::uuid`, id).Scan(&count, &enabled, &message); err != nil || count != 1 || enabled || !strings.Contains(message, "上限") {
		t.Fatal("反复开关绕过了次数上限", err, count, enabled, message)
	}
}

func TestFutureLeasePolicyAppliesToManualRenew(t *testing.T) {
	s, host, network := reliabilityFixture(t)
	ctx := context.Background()
	id := reliabilityInstance(t, s, host, network, "lease-cap-isolated", true)
	p, err := s.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.MaxFutureLeaseHours = 2
	if err = s.SavePolicy(ctx, "admin", p); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RenewInstance(ctx, "isolated-user", false, id, 3, "隔离上限测试"); err == nil {
		t.Fatal("短续期绕过未来租期上限")
	}
}

func TestDelegationRoutingAndExpiry(t *testing.T) {
	db := reliabilityDB(t, false)
	s := &Service{DB: db}
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO users(username,role,password_hash) VALUES('reviewer-a','ADMIN','hash'),('reviewer-b','ADMIN','hash'); INSERT INTO approval_delegations VALUES('reviewer-a','reviewer-b',now()-interval '1 hour',now()+interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.insertApproval(ctx, "requester", "CREATE", "", 336, "隔离代理测试", []byte(`{"instance_name":"delegation"}`)); err != nil {
		t.Fatal(err)
	}
	var assigned, from string
	if err := db.QueryRow(ctx, `SELECT assigned_reviewer,coalesce(delegated_from,'') FROM approval_requests`).Scan(&assigned, &from); err != nil || assigned != "reviewer-b" {
		t.Fatal("未路由到代理人", err, assigned, from)
	}
	if _, err := db.Exec(ctx, `UPDATE approval_requests SET assigned_reviewer='reviewer-b',delegated_from='reviewer-a'; UPDATE approval_delegations SET starts_at=now()-interval '2 hours',ends_at=now()-interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshDelegations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT assigned_reviewer,coalesce(delegated_from,'') FROM approval_requests`).Scan(&assigned, &from); err != nil || assigned != "reviewer-a" || from != "" {
		t.Fatal("到期后未恢复原审批人", err, assigned, from)
	}
	if err := s.SetAutoRenew(ctx, "nobody", false, "invalid", true, 24, 3); err == nil {
		t.Fatal("无效实例参数未拒绝")
	}
}
