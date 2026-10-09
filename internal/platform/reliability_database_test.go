package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"vmp-backend/internal/migrate"
	"vmp-backend/migrations"
)

// 所有测试使用随机独立命名空间和假任务结果，不连接 Agent，不操作任何真实虚机。
func reliabilityDB(t *testing.T, legacy bool) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("VMP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("未配置 VMP_TEST_DATABASE_URL，跳过隔离数据库回归")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("reliability_test_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("清理隔离命名空间失败：%v", err)
		}
		admin.Close()
	})
	if !legacy {
		if err := migrate.Run(ctx, pool); err != nil {
			t.Fatal(err)
		}
	} else {
		files, err := migrations.Files.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
		for _, file := range files {
			if file.IsDir() || file.Name() >= "017_" || !strings.HasSuffix(file.Name(), ".sql") {
				continue
			}
			data, err := migrations.Files.ReadFile(file.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pool.Exec(ctx, string(data)); err != nil {
				t.Fatalf("%s：%v", file.Name(), err)
			}
		}
	}
	return pool
}

func reliabilityFixture(t *testing.T) (*Service, string, string) {
	t.Helper()
	pool := reliabilityDB(t, false)
	ctx := context.Background()
	var host, network string
	if err := pool.QueryRow(ctx, `INSERT INTO hosts(name,status,agent_mode,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb) VALUES('isolated-host','ACTIVE','kvm',32,65536,1000,32,65536,1000) RETURNING id::text`).Scan(&host); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO networks(name,cidr,gateway,dns_servers,bridge) VALUES('isolated-net','10.88.0.0/24','10.88.0.1','{10.88.0.1}','br0') RETURNING id::text`).Scan(&network); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO ip_addresses(network_id,address) SELECT $1::uuid,('10.88.0.'||n)::inet FROM generate_series(10,30) n`, network); err != nil {
		t.Fatal(err)
	}
	return &Service{DB: pool}, host, network
}

func reliabilityInstance(t *testing.T, s *Service, host, network, name string, ready bool) string {
	t.Helper()
	result, err := s.CreateApplication(context.Background(), "isolated-user", CreateApplicationInput{InstanceName: name, Purpose: "隔离 P1 回归", FlavorID: "c1m2", ImageID: "ubuntu-2204", NetworkID: network, LeaseHours: 1})
	if err != nil {
		t.Fatal(err)
	}
	id := result["instance_id"].(string)
	if ready {
		task, err := s.PollTask(context.Background(), host)
		if err != nil {
			t.Fatal(err)
		}
		var ip string
		if err := s.DB.QueryRow(context.Background(), `SELECT host(ip_address) FROM instances WHERE id=$1::uuid`, id).Scan(&ip); err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteTask(context.Background(), host, task["id"].(string), TaskResult{ClaimToken: task["claim_token"].(string), Success: true, IPAddress: ip, ProviderRef: "isolated-domain"}); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func mustExec(t *testing.T, s *Service, sql string, args ...any) {
	t.Helper()
	if _, err := s.DB.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func stateOf(t *testing.T, s *Service, id string) string {
	t.Helper()
	var state string
	if err := s.DB.QueryRow(context.Background(), `SELECT lifecycle_status FROM instances WHERE id=$1::uuid`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestLeaseAndAllocationDatabase(t *testing.T) {
	ctx := context.Background()
	t.Run("关机到期进入保留并保留IP", func(t *testing.T) {
		s, host, network := reliabilityFixture(t)
		id := reliabilityInstance(t, s, host, network, "stopped", true)
		mustExec(t, s, `UPDATE instances SET lifecycle_status='STOPPED',expires_at=now()-interval '1 day' WHERE id=$1::uuid`, id)
		if err := s.ReconcileInstanceLifecycle(ctx); err != nil {
			t.Fatal(err)
		}
		var hours float64
		var ipState string
		if err := s.DB.QueryRow(ctx, `SELECT extract(epoch FROM retention_until-expires_at)/3600 FROM instances WHERE id=$1::uuid`, id).Scan(&hours); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow(ctx, `SELECT status FROM ip_addresses WHERE instance_id=$1::uuid`, id).Scan(&ipState); err != nil {
			t.Fatal(err)
		}
		if stateOf(t, s, id) != "RETAINED" || hours != 168 || ipState != "ALLOCATED" {
			t.Fatal("到期关机实例未按原租期保留资源")
		}
		if err := s.ReconcileInstanceLifecycle(ctx); err != nil {
			t.Fatal(err)
		}
		mustExec(t, s, `UPDATE instances SET retention_until=now()-interval '1 second' WHERE id=$1::uuid`, id)
		if err := s.ReconcileInstanceLifecycle(ctx); err != nil {
			t.Fatal(err)
		}
		if stateOf(t, s, id) != "DELETING" {
			t.Fatal("保留期结束未删除")
		}
	})
	t.Run("恢复过的自然到期不二次保留", func(t *testing.T) {
		for _, status := range []string{"RUNNING", "STOPPED"} {
			s, host, network := reliabilityFixture(t)
			id := reliabilityInstance(t, s, host, network, "restored", true)
			mustExec(t, s, `UPDATE instances SET lifecycle_status=$2,restore_count=1,expires_at=now()-interval '1 minute' WHERE id=$1::uuid`, id, status)
			if err := s.ReconcileInstanceLifecycle(ctx); err != nil {
				t.Fatal(err)
			}
			task, err := s.PollTask(ctx, host)
			if err != nil || task["type"] != "DELETE_INSTANCE" || stateOf(t, s, id) != "DELETING" {
				t.Fatalf("恢复后的%s实例仍进入二次保留：%v", status, err)
			}
		}
	})
	t.Run("手动释放恢复过实例同规则", func(t *testing.T) {
		s, host, network := reliabilityFixture(t)
		id := reliabilityInstance(t, s, host, network, "manual", true)
		mustExec(t, s, `UPDATE instances SET restore_count=1 WHERE id=$1::uuid`, id)
		result, err := s.PerformInstanceAction(ctx, "isolated-user", false, id, "release")
		if err != nil || result["retention_days"] != 0 || stateOf(t, s, id) != "DELETING" {
			t.Fatal("手动释放和自然到期策略不一致")
		}
	})
	t.Run("规格编辑不影响旧实例及删除扣账", func(t *testing.T) {
		s, host, network := reliabilityFixture(t)
		first := reliabilityInstance(t, s, host, network, "first", true)
		second := reliabilityInstance(t, s, host, network, "second", true)
		mustExec(t, s, `UPDATE flavors SET name='未来规格',cpu=4,memory_mb=8192,disk_gb=100 WHERE id='c1m2'`)
		if _, err := s.PerformInstanceAction(ctx, "isolated-user", false, first, "force_delete"); err != nil {
			t.Fatal(err)
		}
		task, err := s.PollTask(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		result := TaskResult{ClaimToken: task["claim_token"].(string), Success: true}
		if err := s.CompleteTask(ctx, host, task["id"].(string), result); err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteTask(ctx, host, task["id"].(string), result); err != nil {
			t.Fatalf("删除清表后未能确认重复结果：%v", err)
		}
		var cpu, mem, disk int
		var name string
		if err := s.DB.QueryRow(ctx, `SELECT reserved_cpu,reserved_memory_mb,reserved_disk_gb FROM hosts WHERE id=$1::uuid`, host).Scan(&cpu, &mem, &disk); err != nil {
			t.Fatal(err)
		}
		if cpu != 1 || mem != 2048 || disk != 40 {
			t.Fatalf("旧实例扣账不符：%d/%d/%d", cpu, mem, disk)
		}
		if err := s.DB.QueryRow(ctx, `SELECT flavor_name_snapshot FROM instances WHERE id=$1::uuid`, second).Scan(&name); err != nil {
			t.Fatal(err)
		}
		if name == "未来规格" {
			t.Fatal("旧实例名称未快照")
		}
		reliabilityInstance(t, s, host, network, "future", true)
		if err := s.DB.QueryRow(ctx, `SELECT reserved_cpu,reserved_memory_mb,reserved_disk_gb FROM hosts WHERE id=$1::uuid`, host).Scan(&cpu, &mem, &disk); err != nil {
			t.Fatal(err)
		}
		if cpu != 5 || mem != 10240 || disk != 140 {
			t.Fatal("新实例未使用新规格")
		}
	})
}

func TestTaskLeaseRecoveryDatabase(t *testing.T) {
	ctx := context.Background()
	t.Run("结果幂等确认和冲突拒绝", func(t *testing.T) {
		s, host, network := reliabilityFixture(t)
		id := reliabilityInstance(t, s, host, network, "result", false)
		task, err := s.PollTask(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		result := TaskResult{ClaimToken: task["claim_token"].(string), Success: true, IPAddress: "10.88.0.10", ProviderRef: "domain"}
		for range 2 {
			if err := s.CompleteTask(ctx, host, task["id"].(string), result); err != nil {
				t.Fatal(err)
			}
		}
		result.ProviderRef = "different-domain"
		if !errors.Is(s.CompleteTask(ctx, host, task["id"].(string), result), ErrTaskClaimConflict) {
			t.Fatal("冲突结果被覆盖")
		}
		var secretPresent bool
		if err := s.DB.QueryRow(ctx, `SELECT result ? 'claim_token' FROM tasks WHERE id=$1::uuid`, task["id"]).Scan(&secretPresent); err != nil {
			t.Fatal(err)
		}
		if secretPresent || stateOf(t, s, id) != "RUNNING" {
			t.Fatal("结果保存了领取凭证或状态错误")
		}
	})
	t.Run("领取超时重排并拒绝旧令牌", func(t *testing.T) {
		s, host, network := reliabilityFixture(t)
		reliabilityInstance(t, s, host, network, "timeout", false)
		first, err := s.PollTask(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RenewTaskLease(ctx, host, first["id"].(string), first["claim_token"].(string)); err != nil {
			t.Fatal(err)
		}
		mustExec(t, s, `UPDATE tasks SET lease_until=now()-interval '1 second' WHERE id=$1::uuid`, first["id"])
		if !errors.Is(s.CompleteTask(ctx, host, first["id"].(string), TaskResult{ClaimToken: first["claim_token"].(string), Success: true}), ErrTaskClaimConflict) {
			t.Fatal("过期结果未拒绝")
		}
		if err := s.RecoverTaskLeases(ctx); err != nil {
			t.Fatal(err)
		}
		second, err := s.PollTask(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		if first["id"] != second["id"] || first["claim_token"] == second["claim_token"] {
			t.Fatal("未生成新的领取代际")
		}
		if _, err := s.RenewTaskLease(ctx, host, first["id"].(string), first["claim_token"].(string)); !errors.Is(err, ErrTaskClaimConflict) {
			t.Fatal("旧令牌夺回了任务")
		}
		if err := s.CompleteTask(ctx, host, second["id"].(string), TaskResult{ClaimToken: second["claim_token"].(string), Success: true, IPAddress: "10.88.0.10"}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("并发领取同宿主最多一项", func(t *testing.T) {
		s, host, network := reliabilityFixture(t)
		reliabilityInstance(t, s, host, network, "one", false)
		reliabilityInstance(t, s, host, network, "two", false)
		var count atomic.Int32
		var wg sync.WaitGroup
		for range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.PollTask(ctx, host)
				if err == nil {
					count.Add(1)
				} else if !errors.Is(err, pgx.ErrNoRows) {
					t.Errorf("并发领取失败：%v", err)
				}
			}()
		}
		wg.Wait()
		if count.Load() != 1 {
			t.Fatal("同宿主并发领到了多个任务")
		}
	})
	t.Run("重启不确定及超时不得盲重放", func(t *testing.T) {
		for _, expired := range []bool{true, false} {
			s, host, network := reliabilityFixture(t)
			id := reliabilityInstance(t, s, host, network, "reboot", true)
			if _, err := s.PerformInstanceAction(ctx, "isolated-user", false, id, "reboot"); err != nil {
				t.Fatal(err)
			}
			task, err := s.PollTask(ctx, host)
			if err != nil {
				t.Fatal(err)
			}
			if expired {
				mustExec(t, s, `UPDATE tasks SET lease_until=now()-interval '1 second' WHERE id=$1::uuid`, task["id"])
				if err := s.RecoverTaskLeases(ctx); err != nil {
					t.Fatal(err)
				}
			} else if err := s.CompleteTask(ctx, host, task["id"].(string), TaskResult{ClaimToken: task["claim_token"].(string), ErrorCode: "EXECUTION_UNCERTAIN", Error: "中断"}); err != nil {
				t.Fatal(err)
			}
			var status string
			if err := s.DB.QueryRow(ctx, `SELECT status FROM tasks WHERE id=$1::uuid`, task["id"]).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status != "FAILED" {
				t.Fatal("不确定的重启被自动再次执行")
			}
		}
	})
}

func TestApprovalAtomicExecutionDatabase(t *testing.T) {
	ctx := context.Background()
	t.Run("批准落库失败整体回滚后重试只执行一次", func(t *testing.T) {
		s, host, network := reliabilityFixture(t)
		approval, err := s.CreateApplication(ctx, "isolated-user", CreateApplicationInput{InstanceName: "atomic", Purpose: "原子审批", FlavorID: "c1m2", ImageID: "ubuntu-2204", NetworkID: network, LeaseHours: 336})
		if err != nil {
			t.Fatal(err)
		}
		id := approval["id"].(string)
		mustExec(t, s, `CREATE FUNCTION fail_approval_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.status='APPROVED' THEN RAISE EXCEPTION '隔离故障注入'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_approval_result BEFORE UPDATE ON approval_requests FOR EACH ROW EXECUTE FUNCTION fail_approval_result()`)
		if _, err := s.DecideApproval(ctx, "admin", id, "APPROVE", "调整为七天", 168); err == nil {
			t.Fatal("故障未注入")
		}
		var state string
		var instances, reserved, tasks int
		if err := s.DB.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id=$1::uuid`, id).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM instances`).Scan(&instances); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM tasks`).Scan(&tasks); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow(ctx, `SELECT reserved_cpu FROM hosts WHERE id=$1::uuid`, host).Scan(&reserved); err != nil {
			t.Fatal(err)
		}
		if state != "PENDING" || instances != 0 || tasks != 0 || reserved != 0 {
			t.Fatal("审批落库失败产生了孤儿资源或卡住状态")
		}
		mustExec(t, s, `DROP TRIGGER fail_approval_result ON approval_requests;DROP FUNCTION fail_approval_result()`)
		if _, err := s.DecideApproval(ctx, "admin", id, "APPROVE", "调整为七天", 168); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DecideApproval(ctx, "admin2", id, "APPROVE", "重复批准", 336); err == nil {
			t.Fatal("重复批准执行了第二次")
		}
		var hours float64
		if err := s.DB.QueryRow(ctx, `SELECT extract(epoch FROM expires_at-created_at)/3600 FROM instances`).Scan(&hours); err != nil {
			t.Fatal(err)
		}
		if hours != 168 {
			t.Fatal("批准调整值未用于实际创建")
		}
	})
	t.Run("续期并发批准仅延长一次", func(t *testing.T) {
		s, host, network := reliabilityFixture(t)
		id := reliabilityInstance(t, s, host, network, "renew", true)
		var before time.Time
		if err := s.DB.QueryRow(ctx, `SELECT expires_at FROM instances WHERE id=$1::uuid`, id).Scan(&before); err != nil {
			t.Fatal(err)
		}
		approval, err := s.RenewInstance(ctx, "isolated-user", false, id, 336, "长期联调")
		if err != nil {
			t.Fatal(err)
		}
		var approved atomic.Int32
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.DecideApproval(ctx, "admin", approval["id"].(string), "APPROVE", "七天", 168); err == nil {
					approved.Add(1)
				}
			}()
		}
		wg.Wait()
		var after time.Time
		if err := s.DB.QueryRow(ctx, `SELECT expires_at FROM instances WHERE id=$1::uuid`, id).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if approved.Load() != 1 || after.Sub(before) != 168*time.Hour {
			t.Fatal("续期被重复批准执行")
		}
	})
	t.Run("业务失败不预占资源审批可追溯", func(t *testing.T) {
		s, host, network := reliabilityFixture(t)
		approval, err := s.CreateApplication(ctx, "isolated-user", CreateApplicationInput{InstanceName: "failure", Purpose: "失败验收", FlavorID: "c1m2", ImageID: "ubuntu-2204", NetworkID: network, LeaseHours: 336})
		if err != nil {
			t.Fatal(err)
		}
		mustExec(t, s, `UPDATE hosts SET status='CORDONED' WHERE id=$1::uuid`, host)
		if _, err := s.DecideApproval(ctx, "admin", approval["id"].(string), "APPROVE", "同意", 168); err == nil {
			t.Fatal("无宿主仍创建成功")
		}
		var state, errorMessage string
		if err := s.DB.QueryRow(ctx, `SELECT status,result->>'error' FROM approval_requests WHERE id=$1::uuid`, approval["id"]).Scan(&state, &errorMessage); err != nil {
			t.Fatal(err)
		}
		if state != "FAILED" || errorMessage == "" {
			t.Fatal("审批执行失败不可追溯")
		}
	})
	t.Run("恢复批准失败不耗恢复次数且不留下启动任务", func(t *testing.T) {
		s, host, network := reliabilityFixture(t)
		id := reliabilityInstance(t, s, host, network, "restore-atomic", true)
		mustExec(t, s, `UPDATE instances SET lifecycle_status='RETAINED',expires_at=now()-interval '1 hour',retention_until=now()+interval '6 days' WHERE id=$1::uuid`, id)
		approval, err := s.RestoreInstance(ctx, "isolated-user", false, id, 336, "恢复联调")
		if err != nil {
			t.Fatal(err)
		}
		mustExec(t, s, `CREATE FUNCTION reject_restore_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.status='APPROVED' THEN RAISE EXCEPTION '隔离落库故障'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_restore_result BEFORE UPDATE ON approval_requests FOR EACH ROW EXECUTE FUNCTION reject_restore_result()`)
		if _, err := s.DecideApproval(ctx, "admin", approval["id"].(string), "APPROVE", "七天", 168); err == nil {
			t.Fatal("落库故障未注入")
		}
		var count, tasks int
		if err := s.DB.QueryRow(ctx, `SELECT restore_count FROM instances WHERE id=$1::uuid`, id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE resource_id=$1::uuid AND task_type='START_INSTANCE'`, id).Scan(&tasks); err != nil {
			t.Fatal(err)
		}
		if count != 0 || tasks != 0 || stateOf(t, s, id) != "RETAINED" {
			t.Fatal("失败恢复留下了不可恢复的副作用")
		}
		mustExec(t, s, `DROP TRIGGER reject_restore_result ON approval_requests; DROP FUNCTION reject_restore_result()`)
		if _, err := s.DecideApproval(ctx, "admin", approval["id"].(string), "APPROVE", "七天", 168); err != nil {
			t.Fatal(err)
		}
		if stateOf(t, s, id) != "STARTING" {
			t.Fatal("事务恢复失败")
		}
	})
}

func TestAllocationSnapshotUpgradeDatabase(t *testing.T) {
	pool := reliabilityDB(t, true)
	ctx := context.Background()
	var host, application, instance string
	if err := pool.QueryRow(ctx, `INSERT INTO hosts(name,status,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb,reserved_cpu,reserved_memory_mb,reserved_disk_gb) VALUES('old-host','ACTIVE',32,65536,1000,32,65536,1000,0,0,0) RETURNING id::text`).Scan(&host); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO applications(request_no,applicant,instance_name,purpose,flavor_id,image_id,lease_hours,status) VALUES('old-app','owner','old-vm','迁移验证','c1m2','ubuntu-2204',1,'APPROVED') RETURNING id::text`).Scan(&application); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO instances(application_id,host_id,name,lifecycle_status,expires_at) VALUES($1::uuid,$2::uuid,'old-vm','RUNNING',now()+interval '1 hour') RETURNING id::text`, application, host).Scan(&instance); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tasks(idempotency_key,task_type,resource_id,host_id,payload,status) VALUES('old-create','CREATE_INSTANCE',$1::uuid,$2::uuid,'{"cpu":1,"memory_mb":2048,"disk_gb":40}','SUCCEEDED')`, instance, host); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE flavors SET cpu=4,memory_mb=8192,disk_gb=100 WHERE id='c1m2'`); err != nil {
		t.Fatal(err)
	}
	data, err := migrations.Files.ReadFile("017_reliable_execution.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(data)); err != nil {
		t.Fatal(err)
	}
	var cpu, mem, disk int
	if err := pool.QueryRow(ctx, `SELECT reserved_cpu,reserved_memory_mb,reserved_disk_gb FROM hosts WHERE id=$1::uuid`, host).Scan(&cpu, &mem, &disk); err != nil {
		t.Fatal(err)
	}
	if cpu != 1 || mem != 2048 || disk != 40 {
		t.Fatal("迁移使用了被编辑的规格，未从创建负载修复台账")
	}
}

func TestLegacyProcessingMigrationDatabase(t *testing.T) {
	pool := reliabilityDB(t, true)
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO approval_requests(request_no,request_type,applicant,requested_hours,reason,status) VALUES('old-processing','RENEW','owner',336,'旧版执行中断','PROCESSING') RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	data, err := migrations.Files.ReadFile("017_reliable_execution.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(data)); err != nil {
		t.Fatal(err)
	}
	var status string
	var uncertain bool
	if err := pool.QueryRow(ctx, `SELECT status,(result->>'execution_uncertain')::boolean FROM approval_requests WHERE id=$1::uuid`, id).Scan(&status, &uncertain); err != nil {
		t.Fatal(err)
	}
	if status != "FAILED" || !uncertain {
		t.Fatal("旧处理中审批未保守收敛")
	}
	s := &Service{DB: pool}
	if _, err := s.ResubmitApprovalShort(ctx, "owner", false, id, 168, "重提"); err == nil {
		t.Fatal("旧不确定执行被盲重放")
	}
}
