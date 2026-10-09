package platform

import (
	"context"
	"strings"
	"testing"
	"time"
)

func fixtureHeartbeat(s *Service, host string, at time.Time) Heartbeat {
	return Heartbeat{Status: "ACTIVE", AllocatableCPU: 32, AllocatableMemoryMB: 65536, AllocatableDiskGB: 1000, InventoryComplete: true, Facts: HostFacts{BudgetSource: "CONFIGURED_TOTAL", ResourceMeasuredAt: at, SafeAvailableMemoryMB: 65536, SafeAvailableDiskGB: 1000, ReadinessComplete: true, Images: []ImageObservation{{ImageID: "ubuntu-2204", Generation: 1, FileName: "ubuntu-22.04-server-cloudimg-amd64.qcow2", Checksum: strings.Repeat("a", 64), Status: "READY"}}, Networks: []NetworkObservation{{Bridge: "br0", Ready: true}}}}
}

func TestReadinessAndBudgetDatabase(t *testing.T) {
	s, host, network := reliabilityFixture(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(ctx, `INSERT INTO flavors(id,name,cpu,memory_mb,disk_gb) VALUES('big','20GiB',2,20480,10)`); err != nil {
		t.Fatal(err)
	}
	var measured time.Time
	if err := s.DB.QueryRow(ctx, `UPDATE hosts SET safe_available_memory_mb=30720,resource_measured_at=now() WHERE id=$1::uuid RETURNING resource_measured_at`, host).Scan(&measured); err != nil {
		t.Fatal(err)
	}
	create := func(name string) error {
		_, err := s.CreateApplication(ctx, "isolated-user", CreateApplicationInput{InstanceName: name, Purpose: "容量隔离测试", FlavorID: "big", ImageID: "ubuntu-2204", NetworkID: network, LeaseHours: 1})
		return err
	}
	if err := create("first-big"); err != nil {
		t.Fatal(err)
	}
	if err := create("second-big"); err == nil {
		t.Fatal("旧测量的安全余量被重复分配")
	}
	hb := fixtureHeartbeat(s, host, measured)
	hb.Facts.SafeAvailableMemoryMB = 30720
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	if err := create("second-big"); err == nil {
		t.Fatal("重复心跳补回了旧测量的安全余量")
	}
	task, err := s.PollTask(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	var instanceID, ip string
	if err := s.DB.QueryRow(ctx, `SELECT id::text,host(ip_address) FROM instances WHERE name='first-big'`).Scan(&instanceID, &ip); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteTask(ctx, host, task["id"].(string), TaskResult{ClaimToken: task["claim_token"].(string), Success: true, ProviderRef: "owned-budget", IPAddress: ip, DeliveryStatus: "READY"}); err != nil {
		t.Fatal(err)
	}
	hb = fixtureHeartbeat(s, host, time.Now())
	hb.Facts.SafeAvailableMemoryMB = 40960
	hb.Domains = []Domain{{Name: "first-big", ProviderUUID: "owned-budget", PlatformInstanceID: instanceID, Ownership: "MANAGED", State: "running", DeliveryStatus: "READY"}}
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	if err := create("second-big"); err != nil {
		t.Fatalf("新安全余量仍重复减去已驻留预留：%v", err)
	}
	if _, err := s.DB.Exec(ctx, `UPDATE host_networks SET ready=false WHERE host_id=$1::uuid`, host); err != nil {
		t.Fatal(err)
	}
	if err := create("bridge-unready"); err == nil {
		t.Fatal("网桥未就绪仍能调度")
	}
}

func TestFailedCreateRebuildsIPReservationDatabase(t *testing.T) {
	s, host, network := reliabilityFixture(t)
	ctx := context.Background()
	id := reliabilityInstance(t, s, host, network, "retry-pool", false)
	if _, err := s.DB.Exec(ctx, `UPDATE ip_addresses SET status='QUARANTINED' WHERE instance_id IS NULL`); err != nil {
		t.Fatal(err)
	}
	task, err := s.PollTask(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteTask(ctx, host, task["id"].(string), TaskResult{ClaimToken: task["claim_token"].(string), ErrorCode: "IP_ADDRESS_IN_USE", Error: "隔离测试占用"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PerformInstanceAction(ctx, "isolated-user", false, id, "retry"); err == nil {
		t.Fatal("没有空闲IP仍复位创建任务")
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO ip_addresses(network_id,address) VALUES($1::uuid,'10.88.0.100')`, network); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PerformInstanceAction(ctx, "isolated-user", false, id, "retry"); err != nil {
		t.Fatal(err)
	}
	var address, status string
	var reserved int
	if err := s.DB.QueryRow(ctx, `SELECT host(ip.address),ip.status FROM ip_addresses ip WHERE ip.instance_id=$1::uuid`, id).Scan(&address, &status); err != nil || address != "10.88.0.100" || status != "RESERVED" {
		t.Fatal("没有恢复有效IP预留", err)
	}
	if err := s.DB.QueryRow(ctx, `SELECT reserved_memory_mb FROM hosts WHERE id=$1::uuid`, host).Scan(&reserved); err != nil || reserved != 2048 {
		t.Fatal("重试重复占用资源预算", err)
	}
	task, err = s.PollTask(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	if task["payload"].(map[string]any)["ip_address"] != "10.88.0.100" {
		t.Fatal("新地址没有传入执行负载")
	}
}

func TestConservativeDomainReconciliationDatabase(t *testing.T) {
	s, host, network := reliabilityFixture(t)
	ctx := context.Background()
	id := reliabilityInstance(t, s, host, network, "state-observe", true)
	hb := fixtureHeartbeat(s, host, time.Now())
	hb.Domains = []Domain{{Name: "state-observe", ProviderUUID: "isolated-domain", Ownership: "MANAGED", PlatformInstanceID: id, State: "shut off"}}
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := s.DB.QueryRow(ctx, `SELECT lifecycle_status FROM instances WHERE id=$1::uuid`, id).Scan(&status); err != nil || status != "STOPPED" {
		t.Fatal("实际关机状态没有保守修正", err)
	}
	hb.InventoryComplete = false
	hb.Domains = nil
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	var scans int
	if err := s.DB.QueryRow(ctx, `SELECT domain_missing_scans FROM instances WHERE id=$1::uuid`, id).Scan(&scans); err != nil || scans != 0 {
		t.Fatal("不完整清单误认为域丢失", err)
	}
	hb.InventoryComplete = true
	hb.Facts.ResourceMeasuredAt = time.Now().Add(time.Second)
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, `SELECT domain_missing_scans FROM instances WHERE id=$1::uuid`, id).Scan(&scans); err != nil || scans != 1 {
		t.Fatal("同一次扫描重复心跳增加了缺失计数", err)
	}
	if _, err := s.DB.Exec(ctx, `UPDATE instances SET domain_missing_since=now()-interval '1 minute' WHERE id=$1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	for offset := 2; offset <= 3; offset++ {
		hb.Facts.ResourceMeasuredAt = time.Now().Add(time.Duration(offset) * time.Second)
		if err := s.Heartbeat(ctx, host, hb); err != nil {
			t.Fatal(err)
		}
	}
	var provider string
	var ipCount, reserved int
	if err := s.DB.QueryRow(ctx, `SELECT provider_status,lifecycle_status FROM instances WHERE id=$1::uuid`, id).Scan(&provider, &status); err != nil || provider != "MISSING" || status != "STOPPED" {
		t.Fatal("域缺失没有告警或错误改变生命周期", err)
	}
	s.DB.QueryRow(ctx, `SELECT count(*) FROM ip_addresses WHERE instance_id=$1::uuid`, id).Scan(&ipCount)
	s.DB.QueryRow(ctx, `SELECT reserved_memory_mb FROM hosts WHERE id=$1::uuid`, host).Scan(&reserved)
	if ipCount != 1 || reserved != 2048 {
		t.Fatal("漏报错误释放了IP或预算")
	}
}

func TestHeartbeatMeasurementPrecisionDatabase(t *testing.T) {
	s, host, network := reliabilityFixture(t)
	ctx := context.Background()
	id := reliabilityInstance(t, s, host, network, "precision-observe", true)
	base := time.Now().UTC().Truncate(time.Second).Add(2*time.Second + 123456*time.Microsecond)
	hb := fixtureHeartbeat(s, host, base.Add(700*time.Nanosecond))
	hb.Domains = nil
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	check := func(want int) {
		t.Helper()
		var scans int
		var stored, lastInventory time.Time
		var jsonTime string
		if err := s.DB.QueryRow(ctx, `SELECT domain_missing_scans FROM instances WHERE id=$1::uuid`, id).Scan(&scans); err != nil || scans != want {
			t.Fatalf("代际计数错误：实际%d预期%d，错误%v", scans, want, err)
		}
		if err := s.DB.QueryRow(ctx, `SELECT resource_measured_at,last_inventory_at,facts#>>'{host,resource_measured_at}' FROM hosts WHERE id=$1::uuid`, host).Scan(&stored, &lastInventory, &jsonTime); err != nil {
			t.Fatal(err)
		}
		parsed, err := time.Parse(time.RFC3339Nano, jsonTime)
		if err != nil || !parsed.Equal(stored) || stored.Nanosecond()%1000 != 0 || lastInventory.Nanosecond()%1000 != 0 {
			t.Fatal("JSON、资源与清单时间没有统一到数据库微秒精度", err)
		}
	}
	check(1)
	// 完全重发及同一微秒内更早/更晚纳秒均只属于同一代扫描。
	for _, delta := range []time.Duration{700 * time.Nanosecond, 999 * time.Nanosecond, 1 * time.Nanosecond, 0} {
		hb.Facts.ResourceMeasuredAt = base.Add(delta)
		if err := s.Heartbeat(ctx, host, hb); err != nil {
			t.Fatal(err)
		}
		check(1)
	}
	// 更旧的独立微秒测量不能回退资源、清单或缺失计数。
	hb.Facts.ResourceMeasuredAt = base.Add(-time.Microsecond)
	hb.Facts.SafeAvailableMemoryMB = 1
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	check(1)
	var safe int
	if err := s.DB.QueryRow(ctx, `SELECT safe_available_memory_mb FROM hosts WHERE id=$1::uuid`, host).Scan(&safe); err != nil || safe != 65536 {
		t.Fatal("乱序旧测量覆盖了新安全余量", err)
	}
	// 真正推进到下一微秒才算第二代；它的纳秒重发仍不重复。
	hb.Facts.SafeAvailableMemoryMB = 65536
	hb.Facts.ResourceMeasuredAt = base.Add(time.Microsecond + 200*time.Nanosecond)
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	check(2)
	hb.Facts.ResourceMeasuredAt = base.Add(time.Microsecond + 900*time.Nanosecond)
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	check(2)
}

func TestCanonicalMeasurementPrecision(t *testing.T) {
	value := time.Date(2026, 10, 9, 12, 0, 0, 123456789, time.FixedZone("测试时区", 8*3600))
	canonical := canonicalMeasurementTime(value)
	if canonical.Location() != time.UTC || canonical.Nanosecond() != 123456000 || !canonical.Equal(value.Truncate(time.Microsecond)) {
		t.Fatal("测量时间未正确规范化UTC微秒")
	}
	if !canonicalMeasurementTime(time.Time{}).IsZero() {
		t.Fatal("零值测量丢失兼容语义")
	}
}

func TestRemoteImageSyncAndGenerationDatabase(t *testing.T) {
	s, host, _ := reliabilityFixture(t)
	ctx := context.Background()
	checksum := strings.Repeat("b", 64)
	if _, err := s.DB.Exec(ctx, `INSERT INTO images(id,name,os_family,version,file_name,source_type,source_location,checksum,sync_status,enabled,desired_enabled) VALUES('remote','远程测试','ubuntu','24.04','remote.qcow2','remote','https://fixture.example/image',$1,'PENDING',false,true)`, checksum); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO host_credentials(host_id,token_hash) VALUES($1::uuid,gen_random_bytes(32))`, host); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueueImageSync(ctx, "remote", []string{host}); err != nil {
		t.Fatal(err)
	}
	task, err := s.PollTask(ctx, host)
	if err != nil || task["type"] != "SYNC_IMAGE" {
		t.Fatal("没有镜像同步任务", err)
	}
	result := TaskResult{ClaimToken: task["claim_token"].(string), Success: true, ImageID: "remote", ImageChecksum: checksum, ImageFileName: "remote.qcow2", ImageGeneration: 1}
	if err := s.CompleteTask(ctx, host, task["id"].(string), result); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteTask(ctx, host, task["id"].(string), result); err != nil {
		t.Fatal("同步结果重发非幂等", err)
	}
	var state string
	var enabled bool
	if err := s.DB.QueryRow(ctx, `SELECT sync_status,enabled FROM images WHERE id='remote'`).Scan(&state, &enabled); err != nil || state != "READY" || !enabled {
		t.Fatal("同步没有成为可用镜像", err)
	}
	if _, err := s.DB.Exec(ctx, `UPDATE images SET generation=2,checksum=repeat('c',64),sync_status='PENDING',enabled=false WHERE id='remote'`); err != nil {
		t.Fatal(err)
	}
	hb := fixtureHeartbeat(s, host, time.Now())
	hb.Facts.Images = append(hb.Facts.Images, ImageObservation{ImageID: "remote", Generation: 1, FileName: "remote.qcow2", Checksum: checksum, Status: "READY"})
	if err := s.Heartbeat(ctx, host, hb); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, `SELECT enabled FROM images WHERE id='remote'`).Scan(&enabled); err != nil || enabled {
		t.Fatal("旧代次报告重新启用了已变更镜像", err)
	}
}

func TestShortAndLongCreateShareValidationDatabase(t *testing.T) {
	s, host, network := reliabilityFixture(t)
	ctx := context.Background()
	for _, hours := range []int{1, 168, 169, 336} {
		for _, bad := range []CreateApplicationInput{{InstanceName: "bad/name", Purpose: "合法用途"}, {InstanceName: "valid-name", Purpose: "   "}} {
			bad.FlavorID = "c1m2"
			bad.ImageID = "ubuntu-2204"
			bad.NetworkID = network
			bad.LeaseHours = hours
			if _, err := s.CreateApplication(ctx, "isolated-user", bad); err == nil {
				t.Fatal("短/长租期校验不一致")
			}
		}
	}
	var instances, approvals, reserved int
	s.DB.QueryRow(ctx, `SELECT count(*) FROM instances`).Scan(&instances)
	s.DB.QueryRow(ctx, `SELECT count(*) FROM approval_requests`).Scan(&approvals)
	s.DB.QueryRow(ctx, `SELECT reserved_memory_mb FROM hosts WHERE id=$1::uuid`, host).Scan(&reserved)
	if instances != 0 || approvals != 0 || reserved != 0 {
		t.Fatal("无效参数提前占用资源或创建审批")
	}
}
