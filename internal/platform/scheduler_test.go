package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vmp-backend/internal/migrate"
)

func TestSchedulingRanking(t *testing.T) {
	now := time.Now()
	items := []schedulingCandidate{
		{ID: "a", Eligible: true, CreatedAt: now, RemainingMemory: 64000, Score: 0.9, LastSequence: 2},
		{ID: "b", Eligible: true, CreatedAt: now, RemainingMemory: 16000, Score: 0.25, LastSequence: 1},
		{ID: "c", Eligible: true, CreatedAt: now, RemainingMemory: 16000, Score: 0.25, LastSequence: 0},
		{ID: "d", Eligible: false, CreatedAt: now, RemainingMemory: 100000, Score: 0},
	}
	for _, tc := range []struct {
		strategy string
		position schedulerPosition
		want     string
	}{
		{ScheduleMostAvailable, schedulerPosition{}, "a"}, {ScheduleBalanced, schedulerPosition{}, "c"},
		{ScheduleRoundRobin, schedulerPosition{}, "a"}, {ScheduleRoundRobin, schedulerPosition{HostID: "a", CreatedAt: now}, "b"},
		{ScheduleRoundRobin, schedulerPosition{HostID: "c", CreatedAt: now}, "a"},
		// 游标所指宿主被删除后仍从原位置往后，不重置到第一台。
		{ScheduleRoundRobin, schedulerPosition{HostID: "bb", CreatedAt: now}, "c"},
	} {
		copyItems := append([]schedulingCandidate(nil), items...)
		rankSchedulingCandidates(copyItems, tc.strategy, tc.position)
		if copyItems[0].ID != tc.want {
			t.Fatalf("%s：得到 %s，期望 %s", tc.strategy, copyItems[0].ID, tc.want)
		}
	}
}

func schedulerFixture(t *testing.T) (*Service, []string, string) {
	t.Helper()
	s, first, network := reliabilityFixture(t)
	ids := []string{first}
	ctx := context.Background()
	for n := 1; n < 3; n++ {
		var id string
		if err := s.DB.QueryRow(ctx, `INSERT INTO hosts(name,status,agent_mode,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb,budget_source,safe_available_memory_mb,safe_available_disk_gb,resource_measured_at,last_heartbeat_at,created_at) VALUES($1,'ACTIVE','kvm',32,65536,1000,32,65536,1000,'CONFIGURED_TOTAL',65536,1000,now(),now(),now()+make_interval(secs=>$2)) RETURNING id::text`, fmt.Sprintf("isolated-host-%d", n), n).Scan(&id); err != nil {
			t.Fatal(err)
		}
		mustExec(t, s, `INSERT INTO host_images(host_id,image_id,generation,file_name,checksum,status,verified_at) SELECT $1::uuid,id,generation,file_name,repeat('a',64),'READY',now() FROM images WHERE id='ubuntu-2204'`, id)
		mustExec(t, s, `INSERT INTO host_networks(host_id,network_id,bridge,ready) VALUES($1::uuid,$2::uuid,'br0',true)`, id, network)
		ids = append(ids, id)
	}
	return s, ids, network
}

func schedulingInput(network, name string) CreateApplicationInput {
	return CreateApplicationInput{InstanceName: name, Purpose: "仅隔离调度回归，不连接 Agent", FlavorID: "c1m2", ImageID: "ubuntu-2204", NetworkID: network, LeaseHours: 1}
}

func setSchedulingStrategy(t *testing.T, s *Service, strategy string) {
	t.Helper()
	p, err := s.GetPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.SchedulingStrategy = strategy
	if err = s.SavePolicy(context.Background(), "isolated-admin", p); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulingRoundRobinDatabase(t *testing.T) {
	s, hosts, network := schedulerFixture(t)
	ctx := context.Background()
	p, err := s.GetPolicy(ctx)
	if err != nil || p.SchedulingStrategy != ScheduleMostAvailable {
		t.Fatal("升级默认策略错误", p, err)
	}
	setSchedulingStrategy(t, s, ScheduleRoundRobin)
	for i := 0; i < 2; i++ {
		preview, err := s.PreviewScheduling(ctx, SchedulingRequest{FlavorID: "c1m2", ImageID: "ubuntu-2204", NetworkID: network})
		if err != nil || preview["selected_host_id"] != hosts[0] {
			t.Fatal("只读预览错误", preview, err)
		}
	}
	position, _ := s.SchedulingStatus(ctx)
	if position.Sequence != 0 {
		t.Fatal("预览推进了轮询")
	}
	for i, want := range []string{hosts[0], hosts[1], hosts[2], hosts[0], hosts[1], hosts[2]} {
		// 模拟后端重启：服务对象没有内存游标，第二次起全部重新创建。
		service := &Service{DB: s.DB}
		result, err := service.CreateApplication(ctx, "isolated-user", schedulingInput(network, fmt.Sprintf("round-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		var host string
		var decision SchedulingDecision
		var raw []byte
		if err = s.DB.QueryRow(ctx, `SELECT host_id::text,scheduling_decision FROM instances WHERE id=$1::uuid`, result["instance_id"]).Scan(&host, &raw); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &decision); err != nil {
			t.Fatal(err)
		}
		if host != want || decision.Sequence != int64(i+1) || decision.Strategy != ScheduleRoundRobin {
			t.Fatal("轮询或快照错误", host, want, decision)
		}
		var recorded bool
		if err = s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_logs WHERE resource_id=$1 AND detail->'scheduling'->>'host_id'=$2)`, result["id"], want).Scan(&recorded); err != nil || !recorded {
			t.Fatal("调度审计缺失", err)
		}
	}
	before, _ := s.SchedulingStatus(ctx)
	// 无空闲 IP 时资源、任务及游标全部回滚，不消耗一次轮询。
	mustExec(t, s, `UPDATE ip_addresses SET status='QUARANTINED' WHERE instance_id IS NULL`)
	if _, err = s.CreateApplication(ctx, "isolated-user", schedulingInput(network, "no-ip")); err == nil {
		t.Fatal("地址池耗尽仍成功")
	}
	after, _ := s.SchedulingStatus(ctx)
	if before.Sequence != after.Sequence || before.HostID != after.HostID {
		t.Fatal("失败申请推进游标")
	}
	// 旧客户端保存配额时省略新字段，不应重置已选轮询。
	p, _ = s.GetPolicy(ctx)
	p.SchedulingStrategy = ""
	if err = s.SavePolicy(ctx, "old-client", p); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetPolicy(ctx)
	if p.SchedulingStrategy != ScheduleRoundRobin {
		t.Fatal("旧客户端重置策略")
	}
}

func TestSchedulingStrategiesAndExclusionsDatabase(t *testing.T) {
	s, hosts, network := schedulerFixture(t)
	ctx := context.Background()
	// A 剩余内存较多，但 CPU 预算接近满载；均衡应选 B，而非仅看内存。
	mustExec(t, s, `UPDATE hosts SET allocatable_cpu=8,reserved_cpu=7 WHERE id=$1::uuid`, hosts[0])
	mustExec(t, s, `UPDATE hosts SET allocatable_memory_mb=16384 WHERE id=$1::uuid`, hosts[1])
	mustExec(t, s, `UPDATE hosts SET status='CORDONED' WHERE id=$1::uuid`, hosts[2])
	request := SchedulingRequest{FlavorID: "c1m2", ImageID: "ubuntu-2204", NetworkID: network, Strategy: ScheduleMostAvailable}
	preview, err := s.PreviewScheduling(ctx, request)
	if err != nil || preview["selected_host_id"] != hosts[0] {
		t.Fatal("剩余资源优先错误", preview, err)
	}
	request.Strategy = ScheduleBalanced
	preview, err = s.PreviewScheduling(ctx, request)
	if err != nil || preview["selected_host_id"] != hosts[1] {
		t.Fatal("均衡策略错误", preview, err)
	}
	// 预览试选不能保存策略。
	p, _ := s.GetPolicy(ctx)
	if p.SchedulingStrategy != ScheduleMostAvailable {
		t.Fatal("预览擅自保存策略")
	}
	setSchedulingStrategy(t, s, ScheduleBalanced)
	result, err := s.CreateApplication(ctx, "isolated-user", schedulingInput(network, "balanced"))
	if err != nil {
		t.Fatal(err)
	}
	var actual string
	if err = s.DB.QueryRow(ctx, `SELECT host_id::text FROM instances WHERE id=$1::uuid`, result["instance_id"]).Scan(&actual); err != nil || actual != hosts[1] {
		t.Fatal("预览和实际分配不一致", err, actual)
	}
	// 逐项覆盖公共硬条件，任何策略都不能绕过。
	for _, tc := range []struct{ name, sql, reason string }{
		{"暂停", `UPDATE hosts SET status='CORDONED'`, "宿主未启用"},
		{"只读", `UPDATE hosts SET status='ACTIVE',agent_mode='kvm-readonly'`, "可写模式"},
		{"心跳", `UPDATE hosts SET agent_mode='kvm',last_heartbeat_at=now()-interval '1 hour'`, "心跳过期"},
		{"采样", `UPDATE hosts SET last_heartbeat_at=now(),resource_measured_at=now()-interval '1 hour'`, "采样过期"},
		{"内存", `UPDATE hosts SET resource_measured_at=now(),safe_available_memory_mb=0`, "实时内存"},
		{"磁盘", `UPDATE hosts SET safe_available_memory_mb=65536,safe_available_disk_gb=0`, "实时磁盘"},
		{"镜像", `UPDATE hosts SET safe_available_disk_gb=1000;UPDATE host_images SET status='MISSING'`, "镜像未就绪"},
		{"网络", `UPDATE host_images SET status='READY';UPDATE host_networks SET ready=false`, "网络或网桥"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustExec(t, s, tc.sql)
			for _, strategy := range []string{ScheduleMostAvailable, ScheduleBalanced, ScheduleRoundRobin} {
				request.Strategy = strategy
				out, err := s.PreviewScheduling(ctx, request)
				if err != nil || out["selected_host_id"] != nil {
					t.Fatal("绕过硬条件", strategy, out, err)
				}
				for _, host := range out["hosts"].([]schedulingCandidate) {
					if !strings.Contains(strings.Join(host.Reasons, ";"), tc.reason) {
						t.Fatal("缺少明确排除原因", host)
					}
				}
			}
		})
	}
}

func TestSchedulingConcurrentReservationDatabase(t *testing.T) {
	s, _, network := schedulerFixture(t)
	ctx := context.Background()
	setSchedulingStrategy(t, s, ScheduleRoundRobin)
	mustExec(t, s, `UPDATE hosts SET allocatable_cpu=2,allocatable_memory_mb=4096,allocatable_disk_gb=80`)
	for i := 0; i < 12; i++ {
		mustExec(t, s, `INSERT INTO users(username,role,source,password_hash) VALUES($1,'USER','LOCAL','fixture')`, fmt.Sprintf("scheduler-user-%d", i))
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	failures := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := s.CreateApplication(ctx, fmt.Sprintf("scheduler-user-%d", i), schedulingInput(network, fmt.Sprintf("concurrent-%d", i)))
			if err == nil {
				successes.Add(1)
			} else if !strings.Contains(err.Error(), "没有同时满足") {
				failures <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if successes.Load() != 6 {
		t.Fatal("并发可用容量应仅创建六台", successes.Load())
	}
	var hosts int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM hosts WHERE reserved_cpu=2 AND reserved_memory_mb=4096 AND reserved_disk_gb=80`).Scan(&hosts); err != nil || hosts != 3 {
		t.Fatal("轮询不均或发生超配", hosts, err)
	}
	position, err := s.SchedulingStatus(ctx)
	if err != nil || position.Sequence != 6 {
		t.Fatal("失败申请推进了轮询", position, err)
	}
}

func TestSchedulingApprovalUsesCurrentStrategyDatabase(t *testing.T) {
	s, hosts, network := schedulerFixture(t)
	ctx := context.Background()
	in := schedulingInput(network, "approval-scheduling")
	in.LeaseHours = 336
	result, err := s.CreateApplication(ctx, "isolated-user", in)
	if err != nil {
		t.Fatal(err)
	}
	position, _ := s.SchedulingStatus(ctx)
	if position.Sequence != 0 {
		t.Fatal("待审批申请提前调度")
	}
	setSchedulingStrategy(t, s, ScheduleRoundRobin)
	mustExec(t, s, `UPDATE hosts SET status='CORDONED' WHERE id=$1::uuid`, hosts[0])
	approved, err := s.DecideApproval(ctx, "isolated-admin", result["id"].(string), "APPROVE", "隔离批准", 168)
	if err != nil {
		t.Fatal(err)
	}
	instance := approved["result"].(map[string]any)["instance_id"]
	var strategy, host string
	if err = s.DB.QueryRow(ctx, `SELECT scheduling_decision->>'strategy',host_id::text FROM instances WHERE id=$1::uuid`, instance).Scan(&strategy, &host); err != nil || strategy != ScheduleRoundRobin || host != hosts[1] {
		t.Fatal("审批未使用当前策略或未跳过暂停宿主", strategy, host, err)
	}
}

func TestSchedulingMigrationPreservesExistingInstancesDatabase(t *testing.T) {
	s, _, network := schedulerFixture(t)
	ctx := context.Background()
	result, err := s.CreateApplication(ctx, "isolated-user", schedulingInput(network, "before-upgrade"))
	if err != nil {
		t.Fatal(err)
	}
	var reserved int
	if err = s.DB.QueryRow(ctx, `SELECT sum(reserved_memory_mb) FROM hosts`).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	// 只在独立测试 schema 恢复 023 表结构，验证 024 真正增量升级且重启幂等。
	mustExec(t, s, `DROP TABLE scheduler_state;ALTER TABLE platform_policy DROP COLUMN scheduling_strategy;ALTER TABLE hosts DROP COLUMN last_scheduled_sequence,DROP COLUMN last_scheduled_at;ALTER TABLE instances DROP COLUMN scheduling_decision;DELETE FROM schema_migrations WHERE version='024_scheduling_policy.sql'`)
	for i := 0; i < 2; i++ {
		if err = migrate.Run(ctx, s.DB); err != nil {
			t.Fatal(err)
		}
	}
	var kept int
	var empty bool
	if err = s.DB.QueryRow(ctx, `SELECT sum(reserved_memory_mb) FROM hosts`).Scan(&kept); err != nil || kept != reserved {
		t.Fatal("迁移改变资源预占", err)
	}
	if err = s.DB.QueryRow(ctx, `SELECT scheduling_decision='{}'::jsonb FROM instances WHERE id=$1::uuid`, result["instance_id"]).Scan(&empty); err != nil || !empty {
		t.Fatal("历史实例被改写或伪造调度历史", err)
	}
	p, err := s.GetPolicy(ctx)
	if err != nil || p.SchedulingStrategy != ScheduleMostAvailable {
		t.Fatal("旧环境升级未保持原策略", p, err)
	}
}
