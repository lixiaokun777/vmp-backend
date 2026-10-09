package platform

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vmp-backend/internal/migrate"
)

type Service struct {
	DB *pgxpool.Pool
}

type CreateApplicationInput struct {
	InstanceName string `json:"instance_name"`
	Purpose      string `json:"purpose"`
	FlavorID     string `json:"flavor_id"`
	ImageID      string `json:"image_id"`
	NetworkID    string `json:"network_id"`
	LeaseHours   int    `json:"lease_hours"`
}

type HostRegistration struct {
	Name                string `json:"name"`
	Mode                string `json:"mode"`
	ManagementIP        string `json:"management_ip"`
	AllocatableCPU      int    `json:"allocatable_cpu"`
	AllocatableMemoryMB int    `json:"allocatable_memory_mb"`
	AllocatableDiskGB   int    `json:"allocatable_disk_gb"`
}

type Heartbeat struct {
	Status              string    `json:"status"`
	AllocatableCPU      int       `json:"allocatable_cpu"`
	AllocatableMemoryMB int       `json:"allocatable_memory_mb"`
	AllocatableDiskGB   int       `json:"allocatable_disk_gb"`
	Facts               HostFacts `json:"facts"`
	Domains             []Domain  `json:"domains"`
	InventoryComplete   bool      `json:"inventory_complete"`
	Checks              []Check   `json:"checks"`
}

type HostFacts struct {
	Hostname          string   `json:"hostname"`
	Architecture      string   `json:"architecture"`
	KernelVersion     string   `json:"kernel_version"`
	LibvirtURI        string   `json:"libvirt_uri"`
	LibvirtVersion    string   `json:"libvirt_version"`
	HypervisorVersion string   `json:"hypervisor_version"`
	StorageRoot       string   `json:"storage_root"`
	ImageRoot         string   `json:"image_root"`
	Bridges           []string `json:"bridges"`
	TotalMemoryMB     int      `json:"total_memory_mb"`
	AvailableMemoryMB int      `json:"available_memory_mb"`
	StorageFreeGB     int      `json:"storage_free_gb"`
	ConsoleURL        string   `json:"console_url,omitempty"`
}

type Domain struct {
	ProviderUUID       string         `json:"provider_uuid"`
	Name               string         `json:"name"`
	State              string         `json:"state"`
	VCPUs              int            `json:"vcpus"`
	MemoryMB           int            `json:"memory_mb"`
	Ownership          string         `json:"ownership"`
	PlatformInstanceID string         `json:"platform_instance_id,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type TaskResult struct {
	ClaimToken  string `json:"claim_token,omitempty"`
	Success     bool   `json:"success"`
	ProviderRef string `json:"provider_ref"`
	IPAddress   string `json:"ip_address"`
	ErrorCode   string `json:"error_code"`
	Error       string `json:"error"`
}

func New(ctx context.Context, databaseURL string) (*Service, error) {
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate.Run(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return &Service{DB: db}, nil
}

func (s *Service) createApplicationNow(ctx context.Context, actor string, in CreateApplicationInput) (map[string]any, error) {
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	result, err := s.createApplicationTx(ctx, tx, actor, in)
	if err != nil {
		return nil, err
	}
	return result, tx.Commit(ctx)
}

// createApplicationTx 只在调用方事务中预占资源和写任务，审批结果可与执行一起原子提交。
func (s *Service) createApplicationTx(ctx context.Context, tx pgx.Tx, actor string, in CreateApplicationInput) (map[string]any, error) {
	if err := validateCreateInput(in); err != nil {
		return nil, err
	}

	var cpu, memoryMB, diskGB int
	var flavorName string
	if err := tx.QueryRow(ctx, `SELECT cpu, memory_mb, disk_gb,name FROM flavors WHERE id=$1 AND enabled FOR SHARE`, in.FlavorID).Scan(&cpu, &memoryMB, &diskGB, &flavorName); err != nil {
		return nil, fmt.Errorf("invalid flavor: %w", err)
	}
	var imageName, imageFile, imagePath, osFamily string
	if err := tx.QueryRow(ctx, `SELECT name,file_name,CASE WHEN source_type='local' THEN coalesce(source_location,file_name) ELSE file_name END,os_family FROM images WHERE id=$1 AND enabled AND sync_status='READY'`, in.ImageID).Scan(&imageName, &imageFile, &imagePath, &osFamily); err != nil {
		return nil, fmt.Errorf("invalid image: %w", err)
	}

	var hostID, hostName string
	err := tx.QueryRow(ctx, `
		SELECT id::text, name FROM hosts
		WHERE status='ACTIVE'
		  AND agent_mode <> 'kvm-readonly'
		  AND allocatable_cpu-reserved_cpu >= $1
		  AND allocatable_memory_mb-reserved_memory_mb >= $2
		  AND allocatable_disk_gb-reserved_disk_gb >= $3
		ORDER BY (allocatable_memory_mb-reserved_memory_mb) DESC, name
		FOR UPDATE SKIP LOCKED LIMIT 1`, cpu, memoryMB, diskGB).Scan(&hostID, &hostName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("no schedulable host has enough capacity")
		}
		return nil, err
	}

	var appID, requestNo string
	err = tx.QueryRow(ctx, `
		INSERT INTO applications(request_no, applicant, instance_name, purpose, flavor_id, image_id, lease_hours, status, approved_at)
		VALUES ('REQ-' || to_char(now(),'YYYYMMDD') || '-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,6)), $1,$2,$3,$4,$5,$6,'APPROVED',now())
		RETURNING id::text, request_no`, actor, in.InstanceName, in.Purpose, in.FlavorID, in.ImageID, in.LeaseHours).Scan(&appID, &requestNo)
	if err != nil {
		return nil, err
	}
	var instanceID string
	err = tx.QueryRow(ctx, `
		INSERT INTO instances(application_id, host_id, name, lifecycle_status, expires_at,allocated_cpu,allocated_memory_mb,allocated_disk_gb,flavor_name_snapshot)
		VALUES ($1::uuid,$2::uuid,$3,'PROVISIONING',now()+make_interval(hours=>$4),$5,$6,$7,$8)
		RETURNING id::text`, appID, hostID, in.InstanceName, in.LeaseHours, cpu, memoryMB, diskGB, flavorName).Scan(&instanceID)
	if err != nil {
		return nil, err
	}
	var ipAddress, networkName, bridge, gateway string
	var prefixLength int
	var dnsServers []string
	if in.NetworkID == "" {
		err = tx.QueryRow(ctx, `SELECT id::text FROM networks WHERE enabled ORDER BY created_at LIMIT 1`).Scan(&in.NetworkID)
		if err != nil {
			return nil, errors.New("no enabled network is available")
		}
	}
	err = tx.QueryRow(ctx, `
		SELECT host(ip.address),n.name,n.bridge,masklen(n.cidr),host(n.gateway),n.dns_servers
		FROM ip_addresses ip JOIN networks n ON n.id=ip.network_id
		WHERE ip.network_id=$1::uuid AND n.enabled AND ip.status='FREE'
		ORDER BY ip.address FOR UPDATE OF ip SKIP LOCKED LIMIT 1`, in.NetworkID).Scan(&ipAddress, &networkName, &bridge, &prefixLength, &gateway, &dnsServers)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("selected network has no free IP address")
		}
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE ip_addresses SET status='RESERVED',instance_id=$1::uuid,reserved_at=now(),updated_at=now() WHERE address=$2::inet`, instanceID, ipAddress)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE instances SET ip_address=$1::inet WHERE id=$2::uuid`, ipAddress, instanceID)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE hosts SET reserved_cpu=reserved_cpu+$1,reserved_memory_mb=reserved_memory_mb+$2,reserved_disk_gb=reserved_disk_gb+$3,updated_at=now() WHERE id=$4::uuid`, cpu, memoryMB, diskGB, hostID)
	if err != nil {
		return nil, err
	}
	password, err := generatePassword(20)
	if err != nil {
		return nil, err
	}
	var passwordHash string
	if err := tx.QueryRow(ctx, `SELECT crypt($1, gen_salt('bf', 12))`, password).Scan(&passwordHash); err != nil {
		return nil, fmt.Errorf("generate password hash: %w", err)
	}
	username := defaultUsername(osFamily)
	payload, err := json.Marshal(map[string]any{"instance_id": instanceID, "name": in.InstanceName, "cpu": cpu, "memory_mb": memoryMB, "disk_gb": diskGB, "image_id": in.ImageID, "image_name": imageName, "image_file": imageFile, "image_path": imagePath, "network_id": in.NetworkID, "network_name": networkName, "bridge": bridge, "mac_address": instanceMAC(instanceID), "ip_address": ipAddress, "prefix_length": prefixLength, "gateway": gateway, "dns_servers": dnsServers, "username": username, "password_hash": passwordHash})
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO tasks(idempotency_key,task_type,resource_id,host_id,payload) VALUES ($1,'CREATE_INSTANCE',$2::uuid,$3::uuid,$4)`, "create:"+instanceID, instanceID, hostID, payload)
	if err != nil {
		return nil, err
	}
	auditDetail, _ := json.Marshal(map[string]any{"instance_id": instanceID, "host_id": hostID, "image_id": in.ImageID, "network_id": in.NetworkID, "ip_address": ipAddress})
	_, _ = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES ($1,'application.create','application',$2,$3)`, actor, appID, auditDetail)
	return map[string]any{"id": appID, "request_no": requestNo, "instance_id": instanceID, "host": hostName, "status": "APPROVED", "connection": map[string]any{"ip_address": ipAddress, "username": username, "password": password, "available_after_provisioning": true}}, nil
}

// instanceMAC 根据实例 UUID 生成稳定的 QEMU MAC，供域定义和 cloud-init 使用同一地址。
func instanceMAC(instanceID string) string {
	digest := sha256.Sum256([]byte(instanceID))
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", digest[0], digest[1], digest[2])
}

func (s *Service) RegisterHost(ctx context.Context, in HostRegistration) (map[string]any, error) {
	if in.Name == "" || in.AllocatableMemoryMB < 1024 {
		return nil, errors.New("invalid host registration")
	}
	if in.Mode == "" {
		in.Mode = "mock"
	}
	if in.Mode != "mock" && in.Mode != "kvm-readonly" && in.Mode != "kvm" {
		return nil, errors.New("unsupported agent mode")
	}
	initialStatus := "ACTIVE"
	if strings.HasPrefix(in.Mode, "kvm") {
		initialStatus = "CORDONED"
	}
	var id, status string
	err := s.DB.QueryRow(ctx, `
		INSERT INTO hosts(name,provider_type,agent_mode,status,management_ip,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb,quota_cpu,quota_memory_mb,quota_disk_gb,last_heartbeat_at)
		VALUES ($1,'kvm',$2,$7,nullif($3,'')::inet,$4,$5,$6,$4,$5,$6,$4,$5,$6,now())
		ON CONFLICT(name) DO UPDATE SET agent_mode=excluded.agent_mode,status=CASE WHEN excluded.agent_mode='kvm-readonly' THEN 'CORDONED' WHEN hosts.status IN ('CORDONED','MAINTENANCE') THEN hosts.status ELSE 'ACTIVE' END,management_ip=excluded.management_ip,
		agent_allocatable_cpu=excluded.agent_allocatable_cpu,agent_allocatable_memory_mb=excluded.agent_allocatable_memory_mb,agent_allocatable_disk_gb=excluded.agent_allocatable_disk_gb,
		allocatable_cpu=least(excluded.agent_allocatable_cpu,coalesce(hosts.quota_cpu,excluded.agent_allocatable_cpu)),allocatable_memory_mb=least(excluded.agent_allocatable_memory_mb,coalesce(hosts.quota_memory_mb,excluded.agent_allocatable_memory_mb)),
		allocatable_disk_gb=least(excluded.agent_allocatable_disk_gb,coalesce(hosts.quota_disk_gb,excluded.agent_allocatable_disk_gb)),last_heartbeat_at=now(),updated_at=now()
		RETURNING id::text,status`, in.Name, in.Mode, in.ManagementIP, in.AllocatableCPU, in.AllocatableMemoryMB, in.AllocatableDiskGB, initialStatus).Scan(&id, &status)
	return map[string]any{"id": id, "name": in.Name, "status": status}, err
}

func (s *Service) Heartbeat(ctx context.Context, hostID string, hb Heartbeat) error {
	status := hb.Status
	if status == "" {
		status = "ACTIVE"
	}
	facts, _ := json.Marshal(map[string]any{"host": hb.Facts, "checks": hb.Checks})
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	inventoryAt := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE hosts SET status=CASE WHEN status IN ('CORDONED','MAINTENANCE') THEN status ELSE $1 END,agent_allocatable_cpu=$2,agent_allocatable_memory_mb=$3,agent_allocatable_disk_gb=$4,allocatable_cpu=least($2,coalesce(quota_cpu,$2)),allocatable_memory_mb=least($3,coalesce(quota_memory_mb,$3)),allocatable_disk_gb=least($4,coalesce(quota_disk_gb,$4)),facts=$5,last_heartbeat_at=now(),last_inventory_at=$6,updated_at=now() WHERE id=$7::uuid`, status, hb.AllocatableCPU, hb.AllocatableMemoryMB, hb.AllocatableDiskGB, facts, inventoryAt, hostID)
	if err == nil && tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	if err != nil {
		return err
	}
	for _, domain := range hb.Domains {
		ownership := domain.Ownership
		if ownership != "MANAGED" && ownership != "EXTERNAL" && ownership != "UNKNOWN" {
			ownership = "UNKNOWN"
		}
		instanceID := domain.PlatformInstanceID
		if !uuidPattern.MatchString(instanceID) {
			instanceID = ""
			if ownership == "MANAGED" {
				ownership = "UNKNOWN"
			}
		}
		metadata, _ := json.Marshal(domain.Metadata)
		_, err = tx.Exec(ctx, `INSERT INTO discovered_instances(host_id,provider_uuid,name,state,vcpus,memory_mb,ownership,platform_instance_id,metadata,last_seen_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,nullif($8,'')::uuid,$9,$10) ON CONFLICT(host_id,provider_uuid) DO UPDATE SET name=excluded.name,state=excluded.state,vcpus=excluded.vcpus,memory_mb=excluded.memory_mb,ownership=excluded.ownership,platform_instance_id=excluded.platform_instance_id,metadata=excluded.metadata,last_seen_at=excluded.last_seen_at`, hostID, domain.ProviderUUID, domain.Name, domain.State, domain.VCPUs, domain.MemoryMB, ownership, instanceID, metadata, inventoryAt)
		if err != nil {
			return err
		}
	}
	if hb.InventoryComplete {
		_, err = tx.Exec(ctx, `DELETE FROM discovered_instances WHERE host_id=$1::uuid AND last_seen_at < $2`, hostID, inventoryAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func generatePassword(length int) (string, error) {
	if length < 12 {
		return "", errors.New("password length must be at least 12")
	}
	groups := []string{"ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789"}
	all := strings.Join(groups, "")
	result := make([]byte, length)
	for index, group := range groups {
		value, err := randomCharacter(group)
		if err != nil {
			return "", err
		}
		result[index] = value
	}
	for index := len(groups); index < length; index++ {
		value, err := randomCharacter(all)
		if err != nil {
			return "", err
		}
		result[index] = value
	}
	for index := len(result) - 1; index > 0; index-- {
		position, err := rand.Int(rand.Reader, big.NewInt(int64(index+1)))
		if err != nil {
			return "", err
		}
		other := int(position.Int64())
		result[index], result[other] = result[other], result[index]
	}
	return string(result), nil
}

func randomCharacter(alphabet string) (byte, error) {
	position, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
	if err != nil {
		return 0, err
	}
	return alphabet[position.Int64()], nil
}

func defaultUsername(osFamily string) string {
	switch strings.ToLower(osFamily) {
	case "ubuntu", "debian":
		return "ubuntu"
	case "centos", "rocky", "almalinux", "rhel":
		return "cloud-user"
	default:
		return "cloud-user"
	}
}

var instanceActionTasks = map[string]struct {
	TaskType     string
	RequiredFrom string
	PendingState string
}{
	"start":  {TaskType: "START_INSTANCE", RequiredFrom: "STOPPED", PendingState: "STARTING"},
	"stop":   {TaskType: "STOP_INSTANCE", RequiredFrom: "RUNNING", PendingState: "STOPPING"},
	"reboot": {TaskType: "REBOOT_INSTANCE", RequiredFrom: "RUNNING", PendingState: "REBOOTING"},
}

func (s *Service) PerformInstanceAction(ctx context.Context, actor string, administrator bool, instanceID, action string) (map[string]any, error) {
	if !uuidPattern.MatchString(instanceID) {
		return nil, errors.New("invalid instance id")
	}
	action = strings.ToLower(strings.TrimSpace(action))
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var owner, hostID, name, username, ipAddress, lifecycleStatus string
	var restoreCount int
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `SELECT a.applicant,i.host_id::text,i.name,coalesce(i.username,''),coalesce(host(i.ip_address),''),i.lifecycle_status,i.expires_at,i.restore_count FROM instances i JOIN applications a ON a.id=i.application_id WHERE i.id=$1::uuid FOR UPDATE OF i`, instanceID).Scan(&owner, &hostID, &name, &username, &ipAddress, &lifecycleStatus, &expiresAt, &restoreCount)
	if err != nil {
		return nil, err
	}
	if owner != actor && !administrator {
		return nil, errors.New("instance does not belong to the current user")
	}
	if action == "reset_password" {
		if lifecycleStatus != "RUNNING" {
			return nil, fmt.Errorf("instance password cannot be reset from status %s", lifecycleStatus)
		}
		if username == "" {
			return nil, errors.New("instance login username is unavailable")
		}
		var activeTasks int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE resource_id=$1::uuid AND status IN ('PENDING','RUNNING')`, instanceID).Scan(&activeTasks); err != nil {
			return nil, err
		}
		if activeTasks > 0 {
			return nil, errors.New("instance still has an active task")
		}
		password, err := generatePassword(20)
		if err != nil {
			return nil, err
		}
		var passwordHash string
		if err := tx.QueryRow(ctx, `SELECT crypt($1,gen_salt('bf',12))`, password).Scan(&passwordHash); err != nil {
			return nil, fmt.Errorf("generate password hash: %w", err)
		}
		payload, err := json.Marshal(map[string]any{"instance_id": instanceID, "name": name, "username": username, "password_hash": passwordHash})
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tasks(idempotency_key,task_type,resource_id,host_id,payload) VALUES ('reset-password:' || $1 || ':' || gen_random_uuid()::text,'RESET_INSTANCE_PASSWORD',$1::uuid,$2::uuid,$3)`, instanceID, hostID, payload); err != nil {
			return nil, err
		}
		_, _ = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'instance.reset_password','instance',$2,$3)`, actor, instanceID, []byte(`{"method":"qemu-guest-agent","secret_persisted":false}`))
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return map[string]any{"id": instanceID, "status": lifecycleStatus, "task_type": "RESET_INSTANCE_PASSWORD", "connection": map[string]any{"ip_address": ipAddress, "username": username, "password": password, "available_after_task": true}}, nil
	}
	if action == "retry" {
		if lifecycleStatus != "ERROR" {
			return nil, fmt.Errorf("instance cannot retry from status %s", lifecycleStatus)
		}
		var failedTaskID string
		err = tx.QueryRow(ctx, `SELECT id::text FROM tasks WHERE resource_id=$1::uuid AND task_type='CREATE_INSTANCE' AND status='FAILED' ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, instanceID).Scan(&failedTaskID)
		if err != nil {
			return nil, errors.New("failed create task was not found")
		}
		if _, err := tx.Exec(ctx, `UPDATE tasks SET status='PENDING',attempt=0,error_message=NULL,result=NULL,available_at=now(),claimed_at=NULL,completed_at=NULL,updated_at=now() WHERE id=$1::uuid`, failedTaskID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE instances SET lifecycle_status='PROVISIONING',updated_at=now() WHERE id=$1::uuid`, instanceID); err != nil {
			return nil, err
		}
		_, _ = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'instance.retry','instance',$2,'{}'::jsonb)`, actor, instanceID)
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return map[string]any{"id": instanceID, "status": "PROVISIONING", "task_type": "CREATE_INSTANCE"}, nil
	}
	if action == "release" {
		var activeTasks int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE resource_id=$1::uuid AND status IN ('PENDING','RUNNING')`, instanceID).Scan(&activeTasks); err != nil {
			return nil, err
		}
		if activeTasks > 0 {
			return nil, errors.New("实例仍有任务正在执行，请等待完成后释放")
		}
		releaseAt := time.Now().UTC()
		if expiresAt.Before(releaseAt) {
			releaseAt = expiresAt
		}
		retentionUntil := releaseAt.Add(retentionDuration)
		if lifecycleStatus == "RETAINED" {
			if err := tx.QueryRow(ctx, `SELECT retention_until FROM instances WHERE id=$1::uuid`, instanceID).Scan(&retentionUntil); err != nil {
				return nil, err
			}
		}
		result, err := s.releaseInstanceTx(ctx, tx, instanceID, hostID, name, lifecycleStatus, restoreCount, retentionUntil, "manual-release")
		if err != nil {
			return nil, err
		}
		detail, _ := json.Marshal(map[string]any{"retention_days": result["retention_days"], "restore_count": restoreCount})
		if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'instance.release','instance',$2,$3)`, actor, instanceID, detail); err != nil {
			return nil, err
		}
		return result, tx.Commit(ctx)
	}
	if action == "force_delete" {
		if lifecycleStatus == "RELEASED" {
			return map[string]any{"id": instanceID, "status": lifecycleStatus}, tx.Commit(ctx)
		}
		if lifecycleStatus != "RUNNING" && lifecycleStatus != "STOPPED" && lifecycleStatus != "RETAINED" && lifecycleStatus != "ERROR" {
			return nil, fmt.Errorf("instance cannot be force deleted from status %s", lifecycleStatus)
		}
		var activeTasks int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE resource_id=$1::uuid AND status IN ('PENDING','RUNNING')`, instanceID).Scan(&activeTasks); err != nil {
			return nil, err
		}
		if activeTasks > 0 {
			return nil, errors.New("instance still has an active task")
		}
		if err := insertInstanceTask(ctx, tx, "DELETE_INSTANCE", instanceID, hostID, name, "force-delete"); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE instances SET lifecycle_status='DELETING',retention_until=now(),updated_at=now() WHERE id=$1::uuid`, instanceID); err != nil {
			return nil, err
		}
		_, _ = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'instance.force_delete','instance',$2,'{"retention_days":0}'::jsonb)`, actor, instanceID)
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return map[string]any{"id": instanceID, "status": "DELETING", "retention_days": 0, "task_type": "DELETE_INSTANCE"}, nil
	}
	spec, ok := instanceActionTasks[action]
	if !ok {
		return nil, errors.New("unsupported instance action")
	}
	if lifecycleStatus != spec.RequiredFrom {
		return nil, fmt.Errorf("instance cannot %s from status %s", action, lifecycleStatus)
	}
	if action == "start" && !expiresAt.After(time.Now()) {
		return nil, errors.New("expired instance must be renewed before it can be started")
	}
	if err := insertInstanceTask(ctx, tx, spec.TaskType, instanceID, hostID, name, "user-action"); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE instances SET lifecycle_status=$1,updated_at=now() WHERE id=$2::uuid`, spec.PendingState, instanceID); err != nil {
		return nil, err
	}
	detail, _ := json.Marshal(map[string]any{"task_type": spec.TaskType})
	_, _ = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,$2,'instance',$3,$4)`, actor, "instance."+action, instanceID, detail)
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"id": instanceID, "status": spec.PendingState, "task_type": spec.TaskType}, nil
}

func (s *Service) renewInstanceNow(ctx context.Context, actor string, administrator bool, instanceID string, hours int, reason string) (map[string]any, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	result, err := s.renewInstanceTx(ctx, tx, actor, administrator, instanceID, hours, reason)
	if err != nil {
		return nil, err
	}
	return result, tx.Commit(ctx)
}

func (s *Service) renewInstanceTx(ctx context.Context, tx pgx.Tx, actor string, administrator bool, instanceID string, hours int, reason string) (map[string]any, error) {
	if !uuidPattern.MatchString(instanceID) || hours < 1 || hours > 720 || strings.TrimSpace(reason) == "" {
		return nil, errors.New("实例、续期小时或续期原因无效")
	}
	var owner, lifecycleStatus string
	err := tx.QueryRow(ctx, `SELECT a.applicant,i.lifecycle_status FROM instances i JOIN applications a ON a.id=i.application_id WHERE i.id=$1::uuid FOR UPDATE OF i`, instanceID).Scan(&owner, &lifecycleStatus)
	if err != nil {
		return nil, err
	}
	if owner != actor && !administrator {
		return nil, errors.New("instance does not belong to the current user")
	}
	if lifecycleStatus == "RETAINED" {
		return nil, errors.New("保留期实例请使用恢复操作")
	}
	if lifecycleStatus != "RUNNING" && lifecycleStatus != "STOPPED" {
		return nil, fmt.Errorf("instance cannot be renewed from status %s", lifecycleStatus)
	}
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `UPDATE instances SET expires_at=greatest(expires_at,now())+make_interval(hours=>$1),updated_at=now() WHERE id=$2::uuid RETURNING expires_at`, hours, instanceID).Scan(&expiresAt)
	if err != nil {
		return nil, err
	}
	detail, _ := json.Marshal(map[string]any{"hours": hours, "reason": reason, "expires_at": expiresAt})
	_, _ = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'instance.renew','instance',$2,$3)`, actor, instanceID, detail)
	return map[string]any{"id": instanceID, "status": lifecycleStatus, "expires_at": expiresAt}, nil
}

func insertInstanceTask(ctx context.Context, tx pgx.Tx, taskType, instanceID, hostID, name, reason string) error {
	payload, err := json.Marshal(map[string]any{"instance_id": instanceID, "name": name, "reason": reason})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO tasks(idempotency_key,task_type,resource_id,host_id,payload) VALUES($1 || ':' || $2 || ':' || gen_random_uuid()::text,$1,$2::uuid,$3::uuid,$4)`, taskType, instanceID, hostID, payload)
	return err
}

func (s *Service) PollTask(ctx context.Context, hostID string) (map[string]any, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// 同一宿主的领取串行化，避免两个连接同时取得不同任务并发操作 libvirt。
	var mode string
	if err := tx.QueryRow(ctx, `SELECT agent_mode FROM hosts WHERE id=$1::uuid FOR UPDATE`, hostID).Scan(&mode); err != nil {
		return nil, err
	}
	if mode == "kvm-readonly" {
		return nil, pgx.ErrNoRows
	}
	var id, typ, claimToken string
	var leaseUntil time.Time
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT t.id::text,t.task_type,t.payload FROM tasks t WHERE t.host_id=$1::uuid AND t.status='PENDING' AND t.available_at<=now() AND NOT EXISTS(SELECT 1 FROM tasks running WHERE running.host_id=t.host_id AND running.status='RUNNING') ORDER BY t.created_at FOR UPDATE OF t SKIP LOCKED LIMIT 1`, hostID).Scan(&id, &typ, &payload)
	if err != nil {
		return nil, err
	}
	err = tx.QueryRow(ctx, `UPDATE tasks SET status='RUNNING',attempt=attempt+1,claimed_at=now(),claim_token=encode(gen_random_bytes(32),'hex'),lease_until=now()+interval '60 seconds',updated_at=now() WHERE id=$1::uuid RETURNING claim_token,lease_until`, id).Scan(&claimToken, &leaseUntil)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	var body any
	_ = json.Unmarshal(payload, &body)
	return map[string]any{"id": id, "type": typ, "payload": body, "claim_token": claimToken, "lease_until": leaseUntil}, nil
}

func (s *Service) CompleteTask(ctx context.Context, hostID, taskID string, result TaskResult) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// 回执不依赖实例/任务外键；删除已完成并清表后，同一结果重发仍能安全确认。
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, taskID); err != nil {
		return err
	}
	claimHash, resultHash := taskResultHashes(result)
	var previousHash string
	err = tx.QueryRow(ctx, `SELECT result_hash FROM task_completion_receipts WHERE task_id=$1::uuid AND host_id=$2::uuid AND claim_token_hash=$3`, taskID, hostID, claimHash).Scan(&previousHash)
	if err == nil {
		if previousHash != resultHash {
			return ErrTaskClaimConflict
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var resourceID, taskType string
	var attempt, maxAttempts int
	var claimMatches bool
	err = tx.QueryRow(ctx, `SELECT resource_id::text,task_type,attempt,max_attempts,(status='RUNNING' AND coalesce(claim_token,'')=$3 AND lease_until>now()) FROM tasks WHERE id=$1::uuid AND host_id=$2::uuid FOR UPDATE`, taskID, hostID, result.ClaimToken).Scan(&resourceID, &taskType, &attempt, &maxAttempts, &claimMatches)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrTaskClaimConflict
	}
	if err != nil {
		return err
	}
	if !claimMatches {
		return ErrTaskClaimConflict
	}
	// 领取凭证仅用于当前请求鉴权，结果和任务历史不得持久化该明文凭证。
	result.ClaimToken = ""
	data, _ := json.Marshal(result)
	if result.Success {
		_, err = tx.Exec(ctx, `UPDATE tasks SET status='SUCCEEDED',result=$1,error_message=NULL,completed_at=now(),updated_at=now() WHERE id=$2::uuid`, data, taskID)
		if err == nil {
			err = s.applySuccessfulTask(ctx, tx, taskType, resourceID, result)
		}
		if err == nil && (taskType == "CREATE_INSTANCE" || taskType == "START_INSTANCE") {
			_, err = tx.Exec(ctx, `UPDATE approval_requests SET status='APPROVED',result=result-'error',updated_at=now() WHERE instance_id=$1::uuid AND status='APPROVED_FAILED' AND ((request_type='CREATE' AND $2='CREATE_INSTANCE') OR (request_type='RESTORE' AND $2='START_INSTANCE'))`, resourceID, taskType)
		}
	} else if taskType == "CREATE_INSTANCE" && result.ErrorCode == "IP_ADDRESS_IN_USE" {
		err = s.retryCreateWithNextIPAddress(ctx, tx, taskID, resourceID, result)
	} else {
		if result.ErrorCode == "EXECUTION_UNCERTAIN" {
			attempt = maxAttempts
		}
		_, err = tx.Exec(ctx, `UPDATE tasks SET status=CASE WHEN $3 OR attempt>=max_attempts THEN 'FAILED' ELSE 'PENDING' END,error_message=$1,available_at=now()+interval '15 seconds',completed_at=CASE WHEN $3 OR attempt>=max_attempts THEN now() ELSE NULL END,updated_at=now() WHERE id=$2::uuid`, result.Error, taskID, result.ErrorCode == "EXECUTION_UNCERTAIN")
		if err == nil && attempt >= maxAttempts {
			if _, err = tx.Exec(ctx, `UPDATE instances SET lifecycle_status=$1,updated_at=now() WHERE id=$2::uuid`, terminalFailureStatus(taskType), resourceID); err != nil {
				return err
			}
			if taskType == "CREATE_INSTANCE" || taskType == "START_INSTANCE" {
				if _, err = tx.Exec(ctx, `UPDATE approval_requests SET status='APPROVED_FAILED',result=result||jsonb_build_object('error',$1::text),updated_at=now() WHERE instance_id=$2::uuid AND status='APPROVED' AND ((request_type='CREATE' AND $3='CREATE_INSTANCE') OR (request_type='RESTORE' AND $3='START_INSTANCE'))`, result.Error, resourceID, taskType); err != nil {
					return err
				}
			}
		}
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO task_completion_receipts(task_id,host_id,claim_token_hash,result_hash) VALUES($1::uuid,$2::uuid,$3,$4)`, taskID, hostID, claimHash, resultHash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// retryCreateWithNextIPAddress 隔离已被外部设备占用的地址，并让原创建任务立即换用下一个候选 IP。
func (s *Service) retryCreateWithNextIPAddress(ctx context.Context, tx pgx.Tx, taskID, instanceID string, result TaskResult) error {
	var occupiedID, networkID, occupiedAddress string
	err := tx.QueryRow(ctx, `SELECT id::text,network_id::text,host(address) FROM ip_addresses WHERE instance_id=$1::uuid FOR UPDATE`, instanceID).Scan(&occupiedID, &networkID, &occupiedAddress)
	if err != nil {
		return fmt.Errorf("locate occupied instance IP: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE ip_addresses SET status='QUARANTINED',instance_id=NULL,reserved_at=NULL,allocated_at=NULL,updated_at=now() WHERE id=$1::uuid`, occupiedID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE instances SET ip_address=NULL,updated_at=now() WHERE id=$1::uuid`, instanceID); err != nil {
		return err
	}

	var nextID, nextAddress string
	err = tx.QueryRow(ctx, `SELECT id::text,host(address) FROM ip_addresses WHERE network_id=$1::uuid AND status='FREE' ORDER BY address FOR UPDATE SKIP LOCKED LIMIT 1`, networkID).Scan(&nextID, &nextAddress)
	if errors.Is(err, pgx.ErrNoRows) {
		message := fmt.Sprintf("IP %s 已被占用，地址池中没有其他可用 IP", occupiedAddress)
		data, _ := json.Marshal(result)
		if _, updateErr := tx.Exec(ctx, `UPDATE tasks SET status='FAILED',result=$1,error_message=$2,completed_at=now(),updated_at=now() WHERE id=$3::uuid`, data, message, taskID); updateErr != nil {
			return updateErr
		}
		if _, updateErr := tx.Exec(ctx, `UPDATE instances SET lifecycle_status='ERROR',updated_at=now() WHERE id=$1::uuid`, instanceID); updateErr != nil {
			return updateErr
		}
		if _, updateErr := tx.Exec(ctx, `UPDATE approval_requests SET status='APPROVED_FAILED',result=coalesce(result,'{}'::jsonb)||jsonb_build_object('error',$1::text),updated_at=now() WHERE instance_id=$2::uuid AND status='APPROVED' AND request_type='CREATE'`, message, instanceID); updateErr != nil {
			return updateErr
		}
		_, updateErr := tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,outcome,detail) VALUES ('system','ip.address.quarantine','ip_address',$1,'SUCCESS',jsonb_build_object('address',$2::text,'reason','icmp_reply','replacement',NULL))`, occupiedID, occupiedAddress)
		return updateErr
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE ip_addresses SET status='RESERVED',instance_id=$1::uuid,reserved_at=now(),updated_at=now() WHERE id=$2::uuid`, instanceID, nextID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE instances SET ip_address=$1::inet,updated_at=now() WHERE id=$2::uuid`, nextAddress, instanceID); err != nil {
		return err
	}
	data, _ := json.Marshal(result)
	message := fmt.Sprintf("IP %s 已被占用，已自动切换为 %s 并重试", occupiedAddress, nextAddress)
	if _, err := tx.Exec(ctx, `UPDATE tasks SET status='PENDING',attempt=0,result=$1,error_message=$2,payload=jsonb_set(payload,'{ip_address}',to_jsonb($3::text),true),available_at=now(),claimed_at=NULL,completed_at=NULL,updated_at=now() WHERE id=$4::uuid`, data, message, nextAddress, taskID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,outcome,detail) VALUES ('system','ip.address.quarantine','ip_address',$1,'SUCCESS',jsonb_build_object('address',$2::text,'reason','icmp_reply','replacement',$3::text,'instance_id',$4::text))`, occupiedID, occupiedAddress, nextAddress, instanceID)
	return err
}

func (s *Service) applySuccessfulTask(ctx context.Context, tx pgx.Tx, taskType, resourceID string, result TaskResult) error {
	switch taskType {
	case "CREATE_INSTANCE":
		if _, err := tx.Exec(ctx, `UPDATE instances SET lifecycle_status='RUNNING',provider_status='RUNNING',provider_ref=$1,ip_address=nullif($2,'')::inet,updated_at=now() WHERE id=$3::uuid`, result.ProviderRef, result.IPAddress, resourceID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE ip_addresses SET status='ALLOCATED',allocated_at=now(),updated_at=now() WHERE instance_id=$1::uuid`, resourceID)
		return err
	case "START_INSTANCE", "REBOOT_INSTANCE":
		_, err := tx.Exec(ctx, `UPDATE instances SET lifecycle_status='RUNNING',provider_status='RUNNING',updated_at=now() WHERE id=$1::uuid`, resourceID)
		return err
	case "STOP_INSTANCE":
		_, err := tx.Exec(ctx, `UPDATE instances SET lifecycle_status=CASE WHEN retention_until IS NOT NULL AND expires_at<=now() THEN 'RETAINED' ELSE 'STOPPED' END,provider_status='STOPPED',updated_at=now() WHERE id=$1::uuid`, resourceID)
		return err
	case "DELETE_INSTANCE":
		var hostID, applicationID string
		var cpu, memoryMB, diskGB int
		if err := tx.QueryRow(ctx, `SELECT host_id::text,application_id::text,allocated_cpu,allocated_memory_mb,allocated_disk_gb FROM instances WHERE id=$1::uuid FOR UPDATE`, resourceID).Scan(&hostID, &applicationID, &cpu, &memoryMB, &diskGB); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ip_addresses SET status='FREE',instance_id=NULL,reserved_at=NULL,allocated_at=NULL,updated_at=now() WHERE instance_id=$1::uuid`, resourceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE hosts SET reserved_cpu=greatest(0,reserved_cpu-$1),reserved_memory_mb=greatest(0,reserved_memory_mb-$2),reserved_disk_gb=greatest(0,reserved_disk_gb-$3),updated_at=now() WHERE id=$4::uuid`, cpu, memoryMB, diskGB, hostID); err != nil {
			return err
		}
		// 宿主机确认删除成功后清除实例与任务，审计流水按合规要求继续保留。
		if _, err := tx.Exec(ctx, `DELETE FROM discovered_instances WHERE platform_instance_id=$1::uuid`, resourceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM tasks WHERE resource_id=$1::uuid`, resourceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM instances WHERE id=$1::uuid`, resourceID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM applications WHERE id=$1::uuid`, applicationID)
		return err
	case "RESET_INSTANCE_PASSWORD":
		return nil
	default:
		return fmt.Errorf("unsupported successful task type %s", taskType)
	}
}

func terminalFailureStatus(taskType string) string {
	switch taskType {
	case "START_INSTANCE":
		return "STOPPED"
	case "STOP_INSTANCE", "REBOOT_INSTANCE":
		return "RUNNING"
	case "DELETE_INSTANCE":
		return "RETAINED"
	case "RESET_INSTANCE_PASSWORD":
		return "RUNNING"
	default:
		return "ERROR"
	}
}

func (s *Service) ReconcileInstanceLifecycle(ctx context.Context) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text,host_id::text,name,lifecycle_status,restore_count,coalesce(retention_until,expires_at+interval '7 days') FROM instances i WHERE ((i.lifecycle_status IN ('RUNNING','STOPPED') AND i.expires_at<=now()) OR (i.lifecycle_status='RETAINED' AND i.retention_until<=now())) AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.resource_id=i.id AND (t.status IN ('PENDING','RUNNING') OR (t.status='FAILED' AND t.updated_at>=i.updated_at AND t.task_type IN ('STOP_INSTANCE','DELETE_INSTANCE')))) ORDER BY coalesce(i.retention_until,i.expires_at) FOR UPDATE OF i SKIP LOCKED LIMIT 50`)
	if err != nil {
		return err
	}
	type candidate struct {
		id, hostID, name, status string
		restoreCount             int
		retentionUntil           time.Time
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.hostID, &item.name, &item.status, &item.restoreCount, &item.retentionUntil); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range candidates {
		reason := "lease-expired"
		if item.status == "RETAINED" {
			reason = "retention-expired"
		}
		result, err := s.releaseInstanceTx(ctx, tx, item.id, item.hostID, item.name, item.status, item.restoreCount, item.retentionUntil, reason)
		if err != nil {
			return err
		}
		detail, _ := json.Marshal(map[string]any{"reason": reason, "retention_days": result["retention_days"], "restore_count": item.restoreCount})
		if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES('system','instance.expire','instance',$1,$2)`, item.id, detail); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) MarkOfflineHosts(ctx context.Context) {
	_, _ = s.DB.Exec(ctx, `UPDATE hosts SET status='OFFLINE',updated_at=now() WHERE status IN ('ACTIVE','DEGRADED') AND last_heartbeat_at < now()-interval '45 seconds'`)
}

func StartReconciler(ctx context.Context, service *Service) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			service.MarkOfflineHosts(ctx)
			if err := service.RecoverTaskLeases(ctx); err != nil {
				fmt.Printf("recover task leases: %v\n", err)
			}
			if err := service.ExpirePendingApprovals(ctx); err != nil {
				fmt.Printf("expire pending approvals: %v\n", err)
			}
			if err := service.ReconcileInstanceLifecycle(ctx); err != nil {
				fmt.Printf("reconcile instance lifecycle: %v\n", err)
			}
		}
	}
}
