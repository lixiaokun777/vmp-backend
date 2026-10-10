package platform

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func ipProbeFixture(t *testing.T) (*Service, string, string) {
	t.Helper()
	s, host, network := reliabilityFixture(t)
	mustExec(t, s, `INSERT INTO users(username,role,source,password_hash) VALUES('probe-admin','ADMIN','LOCAL','fixture-only')`)
	mustExec(t, s, `INSERT INTO host_credentials(host_id,token_hash) VALUES($1::uuid,digest('isolated-probe-fixture','sha256'))`, host)
	return s, host, network
}

func completeProbeFixture(t *testing.T, s *Service, host, status string) map[string]any {
	t.Helper()
	ctx := context.Background()
	task, err := s.PollTask(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	if task["type"] != "PROBE_IP_ADDRESS" {
		t.Fatal("没有领取到复核任务")
	}
	address := task["payload"].(map[string]any)["ip_address"].(string)
	result := TaskResult{ClaimToken: task["claim_token"].(string), Success: true, IPAddress: address, IPProbeStatus: status, IPProbeMessage: "隔离夹具ARP探测"}
	if err = s.CompleteTask(ctx, host, task["id"].(string), result); err != nil {
		t.Fatal(err)
	}
	return task
}

func failedPoolFixture(t *testing.T) (*Service, string, string, string) {
	t.Helper()
	s, host, network := ipProbeFixture(t)
	ctx := context.Background()
	id := reliabilityInstance(t, s, host, network, "probe-recovery", false)
	mustExec(t, s, `UPDATE ip_addresses SET status='QUARANTINED' WHERE instance_id IS NULL`)
	task, err := s.PollTask(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	address := task["payload"].(map[string]any)["ip_address"].(string)
	if err = s.CompleteTask(ctx, host, task["id"].(string), TaskResult{ClaimToken: task["claim_token"].(string), ErrorCode: "IP_ADDRESS_IN_USE", IPAddress: address, IPProbeStatus: "IN_USE", IPProbeMessage: "ARP收到真实响应", Error: "冲突"}); err != nil {
		t.Fatal(err)
	}
	if stateOf(t, s, id) != "ERROR" {
		t.Fatal("地址耗尽没有留下失败实例")
	}
	return s, host, network, id
}

func TestIPProbeMissingEvidenceDoesNotQuarantineDatabase(t *testing.T) {
	for _, kind := range []string{"legacy", "probe_error", "wrong_target", "existing_domain", "expired"} {
		t.Run(kind, func(t *testing.T) {
			s, host, network := ipProbeFixture(t)
			ctx := context.Background()
			id := reliabilityInstance(t, s, host, network, "proof-"+strings.ReplaceAll(kind, "_", "-"), false)
			task, err := s.PollTask(ctx, host)
			if err != nil {
				t.Fatal(err)
			}
			address := task["payload"].(map[string]any)["ip_address"].(string)
			result := TaskResult{ClaimToken: task["claim_token"].(string), ErrorCode: "IP_ADDRESS_IN_USE", Error: "探测失败", IPAddress: address}
			switch kind {
			case "probe_error":
				result.ErrorCode = "IP_PROBE_FAILED"
			case "wrong_target":
				result.IPProbeStatus = "IN_USE"
				result.IPAddress = "10.88.0.250"
			case "existing_domain":
				result.IPProbeStatus = "IN_USE"
				result.ProviderRef = "existing-domain"
			case "expired":
				result.IPProbeStatus = "IN_USE"
				mustExec(t, s, `UPDATE instances SET expires_at=now()-interval '1 second' WHERE id=$1::uuid`, id)
			}
			if err = s.CompleteTask(ctx, host, task["id"].(string), result); err != nil {
				t.Fatal(err)
			}
			var quarantine, free, bound int
			var saved string
			if err = s.DB.QueryRow(ctx, `SELECT count(*) FILTER(WHERE status='QUARANTINED'),count(*) FILTER(WHERE status='FREE'),count(*) FILTER(WHERE instance_id=$2::uuid) FROM ip_addresses WHERE network_id=$1::uuid`, network, id).Scan(&quarantine, &free, &bound); err != nil {
				t.Fatal(err)
			}
			if err = s.DB.QueryRow(ctx, `SELECT host(ip_address) FROM instances WHERE id=$1::uuid`, id).Scan(&saved); err != nil {
				t.Fatal(err)
			}
			if quarantine != 0 || free != 20 || bound != 1 || saved != address {
				t.Fatal("缺证据、错误目标、既有域或过期回调污染地址池")
			}
			if kind == "expired" && stateOf(t, s, id) != "ERROR" {
				t.Fatal("过期任务没有停止")
			}
		})
	}
}

func TestIPProbeAdministratorReleaseAndDuplicatesDatabase(t *testing.T) {
	s, host, network := ipProbeFixture(t)
	ctx := context.Background()
	id := reliabilityInstance(t, s, host, network, "protected-retained", true)
	mustExec(t, s, `UPDATE instances SET lifecycle_status='RETAINED',retention_until=now()+interval '6 days' WHERE id=$1::uuid`, id)
	var target, protected string
	if err := s.DB.QueryRow(ctx, `UPDATE ip_addresses SET status='QUARANTINED' WHERE address='10.88.0.11' RETURNING id::text`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, `SELECT id::text FROM ip_addresses WHERE instance_id=$1::uuid`, id).Scan(&protected); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProbeIPAddress(ctx, "probe-admin", protected, true); err == nil {
		t.Fatal("保留期已绑定IP可复核解除")
	}
	first, err := s.ProbeIPAddress(ctx, "probe-admin", target, false)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 12)
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.ProbeIPAddress(ctx, "probe-admin", target, true)
			if e != nil {
				failures <- e
			} else if r["task_id"] != first["task_id"] || r["already_pending"] != true {
				failures <- errors.New("并发请求重复排队或提高既有解除权限")
			}
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	task := completeProbeFixture(t, s, host, "FREE")
	var state, probe string
	if err = s.DB.QueryRow(ctx, `SELECT status,last_probe_status FROM ip_addresses WHERE id=$1::uuid`, target).Scan(&state, &probe); err != nil {
		t.Fatal(err)
	}
	if state != "QUARANTINED" || probe != "FREE" {
		t.Fatal("纯复核偷偷解除隔离")
	}
	if _, err = s.ProbeIPAddress(ctx, "probe-admin", target, true); err != nil {
		t.Fatal(err)
	}
	completeProbeFixture(t, s, host, "FREE")
	if err = s.DB.QueryRow(ctx, `SELECT status FROM ip_addresses WHERE id=$1::uuid`, target).Scan(&state); err != nil || state != "FREE" {
		t.Fatal("成功FREE没有解除隔离", err)
	}
	oldResult := TaskResult{ClaimToken: task["claim_token"].(string), Success: true, IPAddress: task["payload"].(map[string]any)["ip_address"].(string), IPProbeStatus: "FREE", IPProbeMessage: "隔离夹具ARP探测"}
	if err = s.CompleteTask(ctx, host, task["id"].(string), oldResult); err != nil {
		t.Fatal("同claim丢ACK重发非幂等", err)
	}
	if err = s.DB.QueryRow(ctx, `SELECT status FROM ip_addresses WHERE id=$1::uuid`, protected).Scan(&state); err != nil || state != "ALLOCATED" {
		t.Fatal("已绑定保留期IP被改变", err)
	}
}

func TestIPProbeTargetErrorAndRevokedAuthorityDatabase(t *testing.T) {
	for _, kind := range []string{"wrong_ip", "missing_status", "probe_error", "network_disabled", "admin_disabled", "lease_expired", "readonly"} {
		t.Run(kind, func(t *testing.T) {
			s, host, network := ipProbeFixture(t)
			ctx := context.Background()
			var ip string
			if err := s.DB.QueryRow(ctx, `UPDATE ip_addresses SET status='QUARANTINED' WHERE address='10.88.0.11' RETURNING id::text`).Scan(&ip); err != nil {
				t.Fatal(err)
			}
			if kind == "readonly" {
				mustExec(t, s, `UPDATE hosts SET agent_mode='kvm-readonly' WHERE id=$1::uuid`, host)
				if _, err := s.ProbeIPAddress(ctx, "probe-admin", ip, true); err == nil {
					t.Fatal("只读宿主接收探测")
				}
				return
			}
			if _, err := s.ProbeIPAddress(ctx, "probe-admin", ip, true); err != nil {
				t.Fatal(err)
			}
			task, err := s.PollTask(ctx, host)
			if err != nil {
				t.Fatal(err)
			}
			result := TaskResult{ClaimToken: task["claim_token"].(string), Success: true, IPAddress: "10.88.0.11", IPProbeStatus: "FREE", IPProbeMessage: "夹具空闲"}
			switch kind {
			case "wrong_ip":
				result.IPAddress = "10.88.0.12"
			case "missing_status":
				result.IPProbeStatus = ""
			case "probe_error":
				result.Success = false
				result.ErrorCode = "IP_PROBE_FAILED"
				result.IPProbeStatus = ""
			case "network_disabled":
				mustExec(t, s, `UPDATE networks SET enabled=false WHERE id=$1::uuid`, network)
			case "admin_disabled":
				mustExec(t, s, `UPDATE users SET enabled=false WHERE username='probe-admin'`)
			case "lease_expired":
				mustExec(t, s, `UPDATE tasks SET lease_until=now()-interval '1 second' WHERE id=$1::uuid`, task["id"])
				if err = s.RecoverTaskLeases(ctx); err != nil {
					t.Fatal(err)
				}
				if err = s.CompleteTask(ctx, host, task["id"].(string), result); !errors.Is(err, ErrTaskClaimConflict) {
					t.Fatal("过期claim被接受")
				}
			}
			if kind != "lease_expired" {
				if err = s.CompleteTask(ctx, host, task["id"].(string), result); err != nil {
					t.Fatal(err)
				}
			}
			var state, taskState, message string
			if err = s.DB.QueryRow(ctx, `SELECT status,last_probe_message FROM ip_addresses WHERE id=$1::uuid`, ip).Scan(&state, &message); err != nil {
				t.Fatal(err)
			}
			if err = s.DB.QueryRow(ctx, `SELECT status FROM tasks WHERE id=$1::uuid`, task["id"]).Scan(&taskState); err != nil {
				t.Fatal(err)
			}
			if state != "QUARANTINED" || taskState != "FAILED" || message == "" {
				t.Fatal("异常或权限失效仍解除地址/缺失败反馈")
			}
		})
	}
}

func TestIPProbeAutomaticRecoveryContinuesCreateDatabase(t *testing.T) {
	s, host, _, id := failedPoolFixture(t)
	ctx := context.Background()
	r, err := s.PerformInstanceAction(ctx, "isolated-user", false, id, "retry")
	if err != nil || r["recovery_pending"] != true {
		t.Fatal("没有自动异步复核", err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			again, e := s.PerformInstanceAction(ctx, "isolated-user", false, id, "retry")
			if e != nil {
				failures <- e
			} else if again["task_id"] != r["task_id"] {
				failures <- errors.New("重复重试创建第二复核")
			}
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	completeProbeFixture(t, s, host, "IN_USE")
	second := completeProbeFixture(t, s, host, "FREE")
	address := second["payload"].(map[string]any)["ip_address"].(string)
	var pending bool
	var reserved, cpu, mem, disk int
	var current string
	if err = s.DB.QueryRow(ctx, `SELECT ip_recovery_pending,host(ip_address) FROM instances WHERE id=$1::uuid`, id).Scan(&pending, &current); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM ip_addresses WHERE instance_id=$1::uuid AND status='RESERVED'`, id).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(ctx, `SELECT reserved_cpu,reserved_memory_mb,reserved_disk_gb FROM hosts WHERE id=$1::uuid`, host).Scan(&cpu, &mem, &disk); err != nil {
		t.Fatal(err)
	}
	if pending || current != address || reserved != 1 || cpu != 1 || mem != 2048 || disk != 40 || stateOf(t, s, id) != "PROVISIONING" {
		t.Fatal("FREE回调未原子接续创建或重复占预算")
	}
	create, err := s.PollTask(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	if create["type"] != "CREATE_INSTANCE" || create["payload"].(map[string]any)["ip_address"] != address {
		t.Fatal("新的安全地址未传入原创建任务")
	}
}

func TestIPProbeRecoveryCancelledExpiredAndToolErrorDatabase(t *testing.T) {
	for _, kind := range []string{"cancelled", "expired", "disabled_owner", "probe_error"} {
		t.Run(kind, func(t *testing.T) {
			s, host, _, id := failedPoolFixture(t)
			ctx := context.Background()
			if _, err := s.PerformInstanceAction(ctx, "isolated-user", false, id, "retry"); err != nil {
				t.Fatal(err)
			}
			task, err := s.PollTask(ctx, host)
			if err != nil {
				t.Fatal(err)
			}
			result := TaskResult{ClaimToken: task["claim_token"].(string), Success: true, IPAddress: task["payload"].(map[string]any)["ip_address"].(string), IPProbeStatus: "FREE", IPProbeMessage: "夹具空闲"}
			switch kind {
			case "cancelled":
				if _, err = s.PerformInstanceAction(ctx, "isolated-user", false, id, "force_delete"); err != nil {
					t.Fatal(err)
				}
				if err = s.CompleteTask(ctx, host, task["id"].(string), result); !errors.Is(err, ErrTaskClaimConflict) {
					t.Fatal("已取消探测仍完成")
				}
			case "expired":
				mustExec(t, s, `UPDATE instances SET expires_at=now()-interval '1 second' WHERE id=$1::uuid`, id)
			case "disabled_owner":
				mustExec(t, s, `UPDATE users SET enabled=false WHERE username='isolated-user'`)
			case "probe_error":
				result.Success = false
				result.IPProbeStatus = ""
				result.ErrorCode = "IP_PROBE_FAILED"
				result.Error = "ARP工具不可用"
			}
			if kind != "cancelled" {
				if err = s.CompleteTask(ctx, host, task["id"].(string), result); err != nil {
					t.Fatal(err)
				}
			}
			var bound, pendingCreates int
			var pending bool
			if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM ip_addresses WHERE instance_id=$1::uuid`, id).Scan(&bound); err != nil {
				t.Fatal(err)
			}
			if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE resource_id=$1::uuid AND task_type='CREATE_INSTANCE' AND status='PENDING'`, id).Scan(&pendingCreates); err != nil {
				t.Fatal(err)
			}
			if err = s.DB.QueryRow(ctx, `SELECT ip_recovery_pending FROM instances WHERE id=$1::uuid`, id).Scan(&pending); err != nil {
				t.Fatal(err)
			}
			if bound != 0 || pendingCreates != 0 || pending {
				t.Fatal("取消、到期、停用或探测异常仍重建实例")
			}
		})
	}
}

func TestIPProbeRestoreFailureKeepsOriginalRetentionDatabase(t *testing.T) {
	s, host, network := ipProbeFixture(t)
	ctx := context.Background()
	id := reliabilityInstance(t, s, host, network, "restore-probe", true)
	mustExec(t, s, `UPDATE instances SET lifecycle_status='RETAINED',provider_status='STOPPED',expires_at=now()-interval '1 hour',retention_until=now()+interval '6 days' WHERE id=$1::uuid`, id)
	var originalExpiry, originalRetention time.Time
	if err := s.DB.QueryRow(ctx, `SELECT expires_at,retention_until FROM instances WHERE id=$1::uuid`, id).Scan(&originalExpiry, &originalRetention); err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"IP_ADDRESS_IN_USE", "IP_PROBE_FAILED"} {
		if _, err := s.RestoreInstance(ctx, "isolated-user", false, id, 8, "重新接入"); err != nil {
			t.Fatal(err)
		}
		task, err := s.PollTask(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.CompleteTask(ctx, host, task["id"].(string), TaskResult{ClaimToken: task["claim_token"].(string), ErrorCode: failure, Error: "保持原盘和IP"}); err != nil {
			t.Fatal(err)
		}
		var expiry, retention time.Time
		var count, bound int
		if err = s.DB.QueryRow(ctx, `SELECT expires_at,retention_until,restore_count FROM instances WHERE id=$1::uuid`, id).Scan(&expiry, &retention, &count); err != nil {
			t.Fatal(err)
		}
		if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM ip_addresses WHERE instance_id=$1::uuid AND status='ALLOCATED'`, id).Scan(&bound); err != nil {
			t.Fatal(err)
		}
		if !expiry.Equal(originalExpiry) || !retention.Equal(originalRetention) || count != 0 || bound != 1 || stateOf(t, s, id) != "RETAINED" {
			t.Fatal("恢复失败丢失原保留期或消耗恢复次数/IP")
		}
	}
	if _, err := s.RestoreInstance(ctx, "isolated-user", false, id, 8, "冲突解除后恢复"); err != nil {
		t.Fatal(err)
	}
	task, err := s.PollTask(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteTask(ctx, host, task["id"].(string), TaskResult{ClaimToken: task["claim_token"].(string), Success: true, DeliveryStatus: "READY"}); err != nil {
		t.Fatal(err)
	}
	var count int
	var noRetention bool
	if err = s.DB.QueryRow(ctx, `SELECT restore_count,retention_until IS NULL FROM instances WHERE id=$1::uuid`, id).Scan(&count, &noRetention); err != nil {
		t.Fatal(err)
	}
	if count != 1 || !noRetention || stateOf(t, s, id) != "RUNNING" {
		t.Fatal("只有成功恢复才能消费一次恢复机会")
	}
}

func TestIPProbeExpiredCreateCannotBePolledDatabase(t *testing.T) {
	s, host, network := ipProbeFixture(t)
	id := reliabilityInstance(t, s, host, network, "expired-poll", false)
	ctx := context.Background()
	mustExec(t, s, `UPDATE instances SET expires_at=now()-interval '1 second' WHERE id=$1::uuid`, id)
	if _, err := s.PollTask(ctx, host); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("过期创建仍被下发", err)
	}
	if stateOf(t, s, id) != "ERROR" {
		t.Fatal("过期创建缺终态反馈")
	}
}

func TestIPProbeQueuedTimeoutDoesNotReserveAddressDatabase(t *testing.T) {
	s, host, _, id := failedPoolFixture(t)
	ctx := context.Background()
	if _, err := s.PerformInstanceAction(ctx, "isolated-user", false, id, "retry"); err != nil {
		t.Fatal(err)
	}
	mustExec(t, s, `UPDATE tasks SET created_at=now()-interval '11 minutes' WHERE task_type='PROBE_IP_ADDRESS' AND status='PENDING'`)
	if err := s.RecoverTaskLeases(ctx); err != nil {
		t.Fatal(err)
	}
	var pending bool
	var active, bound int
	if err := s.DB.QueryRow(ctx, `SELECT ip_recovery_pending FROM instances WHERE id=$1::uuid`, id).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE task_type='PROBE_IP_ADDRESS' AND status IN('PENDING','RUNNING')`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM ip_addresses WHERE instance_id=$1::uuid`, id).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if pending || active != 0 || bound != 0 {
		t.Fatal("离线排队没有按10分钟收口或偷偷恢复地址")
	}
	if _, err := s.PerformInstanceAction(ctx, "isolated-user", false, id, "retry"); err != nil {
		t.Fatal("超时后无法明确重提复核", err)
	}
	_ = host
}

func TestIPProbeBatchBoundsAndFairProgressDatabase(t *testing.T) {
	s, host, network := ipProbeFixture(t)
	ctx := context.Background()
	mustExec(t, s, `UPDATE ip_addresses SET status='QUARANTINED' WHERE network_id=$1::uuid`, network)
	mustExec(t, s, `INSERT INTO ip_addresses(network_id,address,status) SELECT $1::uuid,('10.88.0.'||n)::inet,'QUARANTINED' FROM generate_series(31,90)n`, network)
	first, err := s.ProbeQuarantinedNetwork(ctx, "probe-admin", network, false, 64)
	if err != nil {
		t.Fatal(err)
	}
	if first["queued"] != 64 || first["remaining"] != 17 {
		t.Fatal("批量没有64上限和未复核计数")
	}
	for n := 0; n < 64; n++ {
		completeProbeFixture(t, s, host, "IN_USE")
	}
	second, err := s.ProbeQuarantinedNetwork(ctx, "probe-admin", network, false, 17)
	if err != nil {
		t.Fatal(err)
	}
	if second["queued"] != 17 || second["confirmed_in_use"] != 64 {
		t.Fatal("第二批反复探测已确认占用前缀，未推进到未复核地址")
	}
	var stillUnknown int
	if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM ip_addresses WHERE network_id=$1::uuid AND last_probe_status='UNKNOWN'`, network).Scan(&stillUnknown); err != nil {
		t.Fatal(err)
	}
	if stillUnknown != 0 {
		t.Fatal("分批复核未覆盖所有地址")
	}
	if _, err = s.ProbeQuarantinedNetwork(ctx, "probe-admin", network, true, 65); err == nil {
		t.Fatal("超限批量被接受")
	}
}
