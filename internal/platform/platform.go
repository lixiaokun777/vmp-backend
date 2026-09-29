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
	Success     bool   `json:"success"`
	ProviderRef string `json:"provider_ref"`
	IPAddress   string `json:"ip_address"`
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
	return &Service{DB: db}, nil
}

func (s *Service) CreateApplication(ctx context.Context, actor string, in CreateApplicationInput) (map[string]any, error) {
	if in.InstanceName == "" || in.Purpose == "" || in.FlavorID == "" || in.ImageID == "" {
		return nil, errors.New("instance_name, purpose, flavor_id and image_id are required")
	}
	if in.LeaseHours < 1 || in.LeaseHours > 720 {
		return nil, errors.New("lease_hours must be between 1 and 720")
	}
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var cpu, memoryMB, diskGB int
	if err := tx.QueryRow(ctx, `SELECT cpu, memory_mb, disk_gb FROM flavors WHERE id=$1 AND enabled`, in.FlavorID).Scan(&cpu, &memoryMB, &diskGB); err != nil {
		return nil, fmt.Errorf("invalid flavor: %w", err)
	}
	var imageName, imageFile, imagePath, osFamily string
	if err := tx.QueryRow(ctx, `SELECT name,file_name,CASE WHEN source_type='local' THEN coalesce(source_location,file_name) ELSE file_name END,os_family FROM images WHERE id=$1 AND enabled AND sync_status='READY'`, in.ImageID).Scan(&imageName, &imageFile, &imagePath, &osFamily); err != nil {
		return nil, fmt.Errorf("invalid image: %w", err)
	}

	var hostID, hostName string
	err = tx.QueryRow(ctx, `
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
		INSERT INTO instances(application_id, host_id, name, lifecycle_status, expires_at)
		VALUES ($1::uuid,$2::uuid,$3,'PROVISIONING',now()+make_interval(hours=>$4))
		RETURNING id::text`, appID, hostID, in.InstanceName, in.LeaseHours).Scan(&instanceID)
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
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
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

func (s *Service) PerformInstanceAction(ctx context.Context, actor, instanceID, action string) (map[string]any, error) {
	if !uuidPattern.MatchString(instanceID) {
		return nil, errors.New("invalid instance id")
	}
	action = strings.ToLower(strings.TrimSpace(action))
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var owner, hostID, name, lifecycleStatus string
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `SELECT a.applicant,i.host_id::text,i.name,i.lifecycle_status,i.expires_at FROM instances i JOIN applications a ON a.id=i.application_id WHERE i.id=$1::uuid FOR UPDATE OF i`, instanceID).Scan(&owner, &hostID, &name, &lifecycleStatus, &expiresAt)
	if err != nil {
		return nil, err
	}
	if owner != actor {
		return nil, errors.New("instance does not belong to the current user")
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
		switch lifecycleStatus {
		case "RUNNING":
			if err := insertInstanceTask(ctx, tx, "STOP_INSTANCE", instanceID, hostID, name, "manual-release"); err != nil {
				return nil, err
			}
			lifecycleStatus = "STOPPING"
		case "STOPPED":
			lifecycleStatus = "RETAINED"
		case "RETAINED":
			return map[string]any{"id": instanceID, "status": lifecycleStatus}, tx.Commit(ctx)
		default:
			return nil, fmt.Errorf("instance cannot be released from status %s", lifecycleStatus)
		}
		_, err = tx.Exec(ctx, `UPDATE instances SET lifecycle_status=$1,expires_at=least(expires_at,now()),retention_until=now()+interval '7 days',updated_at=now() WHERE id=$2::uuid`, lifecycleStatus, instanceID)
		if err != nil {
			return nil, err
		}
		_, _ = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'instance.release','instance',$2,$3)`, actor, instanceID, []byte(`{"retention_days":7}`))
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return map[string]any{"id": instanceID, "status": lifecycleStatus, "retention_days": 7}, nil
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

func (s *Service) RenewInstance(ctx context.Context, actor, instanceID string, hours int) (map[string]any, error) {
	if !uuidPattern.MatchString(instanceID) || hours < 1 || hours > 720 {
		return nil, errors.New("instance id or renewal hours is invalid")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var owner, hostID, name, lifecycleStatus string
	var retained bool
	err = tx.QueryRow(ctx, `SELECT a.applicant,i.host_id::text,i.name,i.lifecycle_status,i.retention_until IS NOT NULL FROM instances i JOIN applications a ON a.id=i.application_id WHERE i.id=$1::uuid FOR UPDATE OF i`, instanceID).Scan(&owner, &hostID, &name, &lifecycleStatus, &retained)
	if err != nil {
		return nil, err
	}
	if owner != actor {
		return nil, errors.New("instance does not belong to the current user")
	}
	if lifecycleStatus == "DELETING" || lifecycleStatus == "RELEASED" || lifecycleStatus == "PROVISIONING" {
		return nil, fmt.Errorf("instance cannot be renewed from status %s", lifecycleStatus)
	}
	nextStatus := lifecycleStatus
	if retained && (lifecycleStatus == "RETAINED" || lifecycleStatus == "STOPPED") {
		if err := insertInstanceTask(ctx, tx, "START_INSTANCE", instanceID, hostID, name, "renewal"); err != nil {
			return nil, err
		}
		nextStatus = "STARTING"
	}
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `UPDATE instances SET expires_at=greatest(expires_at,now())+make_interval(hours=>$1),retention_until=NULL,lifecycle_status=$2,updated_at=now() WHERE id=$3::uuid RETURNING expires_at`, hours, nextStatus, instanceID).Scan(&expiresAt)
	if err != nil {
		return nil, err
	}
	detail, _ := json.Marshal(map[string]any{"hours": hours, "expires_at": expiresAt})
	_, _ = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'instance.renew','instance',$2,$3)`, actor, instanceID, detail)
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"id": instanceID, "status": nextStatus, "expires_at": expiresAt}, nil
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
	var id, typ string
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT t.id::text,t.task_type,t.payload FROM tasks t JOIN hosts h ON h.id=t.host_id WHERE t.host_id=$1::uuid AND h.agent_mode <> 'kvm-readonly' AND t.status='PENDING' AND t.available_at<=now() ORDER BY t.created_at FOR UPDATE OF t SKIP LOCKED LIMIT 1`, hostID).Scan(&id, &typ, &payload)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE tasks SET status='RUNNING',attempt=attempt+1,claimed_at=now(),updated_at=now() WHERE id=$1::uuid`, id)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	var body any
	_ = json.Unmarshal(payload, &body)
	return map[string]any{"id": id, "type": typ, "payload": body}, nil
}

func (s *Service) CompleteTask(ctx context.Context, hostID, taskID string, result TaskResult) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var resourceID, taskType string
	var attempt, maxAttempts int
	err = tx.QueryRow(ctx, `SELECT resource_id::text,task_type,attempt,max_attempts FROM tasks WHERE id=$1::uuid AND host_id=$2::uuid AND status='RUNNING' FOR UPDATE`, taskID, hostID).Scan(&resourceID, &taskType, &attempt, &maxAttempts)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(result)
	if result.Success {
		_, err = tx.Exec(ctx, `UPDATE tasks SET status='SUCCEEDED',result=$1,error_message=NULL,completed_at=now(),updated_at=now() WHERE id=$2::uuid`, data, taskID)
		if err == nil {
			err = s.applySuccessfulTask(ctx, tx, taskType, resourceID, result)
		}
	} else {
		_, err = tx.Exec(ctx, `UPDATE tasks SET status=CASE WHEN attempt>=max_attempts THEN 'FAILED' ELSE 'PENDING' END,error_message=$1,available_at=now()+interval '15 seconds',completed_at=CASE WHEN attempt>=max_attempts THEN now() ELSE NULL END,updated_at=now() WHERE id=$2::uuid`, result.Error, taskID)
		if err == nil && attempt >= maxAttempts {
			_, _ = tx.Exec(ctx, `UPDATE instances SET lifecycle_status=$1,updated_at=now() WHERE id=$2::uuid`, terminalFailureStatus(taskType), resourceID)
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
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
		var hostID string
		var cpu, memoryMB, diskGB int
		if err := tx.QueryRow(ctx, `SELECT i.host_id::text,f.cpu,f.memory_mb,f.disk_gb FROM instances i JOIN applications a ON a.id=i.application_id JOIN flavors f ON f.id=a.flavor_id WHERE i.id=$1::uuid FOR UPDATE OF i`, resourceID).Scan(&hostID, &cpu, &memoryMB, &diskGB); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE instances SET lifecycle_status='RELEASED',provider_status='DELETED',provider_ref=NULL,ip_address=NULL,updated_at=now() WHERE id=$1::uuid`, resourceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ip_addresses SET status='FREE',instance_id=NULL,reserved_at=NULL,allocated_at=NULL,updated_at=now() WHERE instance_id=$1::uuid`, resourceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE hosts SET reserved_cpu=greatest(0,reserved_cpu-$1),reserved_memory_mb=greatest(0,reserved_memory_mb-$2),reserved_disk_gb=greatest(0,reserved_disk_gb-$3),updated_at=now() WHERE id=$4::uuid`, cpu, memoryMB, diskGB, hostID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE applications SET status='RELEASED' WHERE id=(SELECT application_id FROM instances WHERE id=$1::uuid)`, resourceID)
		return err
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
	rows, err := tx.Query(ctx, `SELECT id::text,host_id::text,name,lifecycle_status FROM instances i WHERE ((i.lifecycle_status='RUNNING' AND i.expires_at<=now()) OR (i.lifecycle_status='RETAINED' AND i.retention_until<=now())) AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.resource_id=i.id AND t.status='FAILED' AND t.updated_at>=i.updated_at AND ((i.lifecycle_status='RUNNING' AND t.task_type='STOP_INSTANCE') OR (i.lifecycle_status='RETAINED' AND t.task_type='DELETE_INSTANCE'))) ORDER BY coalesce(i.retention_until,i.expires_at) FOR UPDATE OF i SKIP LOCKED LIMIT 50`)
	if err != nil {
		return err
	}
	type candidate struct{ id, hostID, name, status string }
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.hostID, &item.name, &item.status); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, item)
	}
	rows.Close()
	for _, item := range candidates {
		taskType, nextStatus, reason := "STOP_INSTANCE", "STOPPING", "lease-expired"
		if item.status == "RETAINED" {
			taskType, nextStatus, reason = "DELETE_INSTANCE", "DELETING", "retention-expired"
		}
		if err := insertInstanceTask(ctx, tx, taskType, item.id, item.hostID, item.name, reason); err != nil {
			return err
		}
		if taskType == "STOP_INSTANCE" {
			_, err = tx.Exec(ctx, `UPDATE instances SET lifecycle_status=$1,retention_until=coalesce(retention_until,now()+interval '7 days'),updated_at=now() WHERE id=$2::uuid`, nextStatus, item.id)
		} else {
			_, err = tx.Exec(ctx, `UPDATE instances SET lifecycle_status=$1,updated_at=now() WHERE id=$2::uuid`, nextStatus, item.id)
		}
		if err != nil {
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
			if err := service.ReconcileInstanceLifecycle(ctx); err != nil {
				fmt.Printf("reconcile instance lifecycle: %v\n", err)
			}
		}
	}
}
