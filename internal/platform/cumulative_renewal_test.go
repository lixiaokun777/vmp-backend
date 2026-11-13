package platform

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCumulativeRenewalBoundary(t *testing.T) {
	created := time.Now()
	limit := created.Add(168 * time.Hour)
	if renewalNeedsApproval(created, limit, 1) {
		t.Fatal("恰好7天不应审批")
	}
	if !renewalNeedsApproval(created, limit.Add(time.Nanosecond), 1) {
		t.Fatal("拆成短续期绕过累计期限")
	}
}

func TestCumulativeRenewalApprovalDatabase(t *testing.T) {
	s, host, network := reliabilityFixture(t)
	ctx := context.Background()
	id := reliabilityInstance(t, s, host, network, "cumulative-renew", true)
	mustExec(t, s, `UPDATE instances SET created_at=now()-interval '6 days',expires_at=now()-interval '6 days'+interval '167 hours' WHERE id=$1::uuid`, id)
	direct, err := s.RenewInstance(ctx, "isolated-user", false, id, 1, "补足7天")
	if err != nil || direct["approval_required"] == true {
		t.Fatal(direct, err)
	}
	var before time.Time
	if err = s.DB.QueryRow(ctx, `SELECT expires_at FROM instances WHERE id=$1::uuid`, id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan map[string]any, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.RenewInstance(ctx, "isolated-user", false, id, 1, "并发短续期")
			if e == nil {
				results <- r
			}
		}()
	}
	wg.Wait()
	close(results)
	var approval map[string]any
	count := 0
	for r := range results {
		count++
		approval = r
	}
	if count != 1 || approval["approval_required"] != true {
		t.Fatal("并发未去重或绕过审批", count, approval)
	}
	var after time.Time
	s.DB.QueryRow(ctx, `SELECT expires_at FROM instances WHERE id=$1::uuid`, id).Scan(&after)
	if !before.Equal(after) {
		t.Fatal("审批前延长了到期时间")
	}
	if _, err = s.DecideApproval(ctx, "isolated-admin", approval["id"].(string), "APPROVE", "调整为两小时", 2); err != nil {
		t.Fatal(err)
	}
	s.DB.QueryRow(ctx, `SELECT expires_at FROM instances WHERE id=$1::uuid`, id).Scan(&after)
	if !after.Equal(before.Add(2 * time.Hour)) {
		t.Fatal("批准时调整租期未执行", before, after)
	}
	next, err := s.RenewInstance(ctx, "isolated-user", false, id, 1, "批准后继续延长")
	if err != nil || next["approval_required"] != true {
		t.Fatal("批准后获得无限续期权限", next, err)
	}
}

func TestAutoRenewCannotExceedCumulativeLimitDatabase(t *testing.T) {
	s, host, network := reliabilityFixture(t)
	ctx := context.Background()
	id := reliabilityInstance(t, s, host, network, "cumulative-auto", true)
	p, err := s.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.AutoRenewEnabled = true
	if err = s.SavePolicy(ctx, "admin", p); err != nil {
		t.Fatal(err)
	}
	mustExec(t, s, `UPDATE instances SET created_at=now()-interval '8 days',expires_at=now()+interval '30 minutes' WHERE id=$1::uuid`, id)
	if err = s.SetAutoRenew(ctx, "isolated-user", false, id, true, 24, 3); err != nil {
		t.Fatal(err)
	}
	var before time.Time
	s.DB.QueryRow(ctx, `SELECT expires_at FROM instances WHERE id=$1::uuid`, id).Scan(&before)
	if err = s.RunAutoRenew(ctx); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	var count int
	var message string
	var after time.Time
	if err = s.DB.QueryRow(ctx, `SELECT a.enabled,a.renewed_count,a.last_error,i.expires_at FROM instance_auto_renew a JOIN instances i ON i.id=a.instance_id WHERE i.id=$1::uuid`, id).Scan(&enabled, &count, &message, &after); err != nil {
		t.Fatal(err)
	}
	if enabled || count != 0 || !before.Equal(after) || !strings.Contains(message, "审批") {
		t.Fatal("自动续期绕过审批", enabled, count, message, after)
	}
}

func TestRenewalApprovalRejectsChangedExpiryDatabase(t *testing.T) {
	s, host, network := reliabilityFixture(t)
	ctx := context.Background()
	id := reliabilityInstance(t, s, host, network, "changed-renewal", true)
	mustExec(t, s, `UPDATE instances SET created_at=now()-interval '8 days' WHERE id=$1::uuid`, id)
	request, err := s.RenewInstance(ctx, "isolated-user", false, id, 1, "历史长租期追加")
	if err != nil || request["approval_required"] != true {
		t.Fatal(request, err)
	}
	mustExec(t, s, `UPDATE instances SET expires_at=expires_at+interval '2 hours' WHERE id=$1::uuid`, id)
	var before, after time.Time
	if err = s.DB.QueryRow(ctx, `SELECT expires_at FROM instances WHERE id=$1::uuid`, id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DecideApproval(ctx, "admin", request["id"].(string), "APPROVE", "原申请已过时", 1); err == nil {
		t.Fatal("旧审批覆盖了新到期时间")
	}
	if err = s.DB.QueryRow(ctx, `SELECT expires_at FROM instances WHERE id=$1::uuid`, id).Scan(&after); err != nil || !before.Equal(after) {
		t.Fatal("拒绝过时审批仍改变到期时间", err)
	}
}
