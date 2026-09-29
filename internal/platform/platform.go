package platform

import (
	"context"
	"crypto/rand"
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
	var imageName, imageFile, osFamily string
	if err := tx.QueryRow(ctx, `SELECT name,file_name,os_family FROM images WHERE id=$1 AND enabled`, in.ImageID).Scan(&imageName, &imageFile, &osFamily); err != nil {
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
	payload, err := json.Marshal(map[string]any{"instance_id": instanceID, "name": in.InstanceName, "cpu": cpu, "memory_mb": memoryMB, "disk_gb": diskGB, "image_id": in.ImageID, "image_name": imageName, "image_file": imageFile, "network_id": in.NetworkID, "network_name": networkName, "bridge": bridge, "ip_address": ipAddress, "prefix_length": prefixLength, "gateway": gateway, "dns_servers": dnsServers, "username": username, "password_hash": passwordHash})
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
		INSERT INTO hosts(name,provider_type,agent_mode,status,management_ip,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,last_heartbeat_at)
		VALUES ($1,'kvm',$2,$7,nullif($3,'')::inet,$4,$5,$6,now())
		ON CONFLICT(name) DO UPDATE SET agent_mode=excluded.agent_mode,status=CASE WHEN excluded.agent_mode='kvm-readonly' THEN 'CORDONED' WHEN hosts.status IN ('CORDONED','MAINTENANCE') THEN hosts.status ELSE 'ACTIVE' END,management_ip=excluded.management_ip,
		allocatable_cpu=excluded.allocatable_cpu,allocatable_memory_mb=excluded.allocatable_memory_mb,
		allocatable_disk_gb=excluded.allocatable_disk_gb,last_heartbeat_at=now(),updated_at=now()
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
	tag, err := tx.Exec(ctx, `UPDATE hosts SET status=CASE WHEN status IN ('CORDONED','MAINTENANCE') THEN status ELSE $1 END,allocatable_cpu=$2,allocatable_memory_mb=$3,allocatable_disk_gb=$4,facts=$5,last_heartbeat_at=now(),last_inventory_at=$6,updated_at=now() WHERE id=$7::uuid`, status, hb.AllocatableCPU, hb.AllocatableMemoryMB, hb.AllocatableDiskGB, facts, inventoryAt, hostID)
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
	var resourceID string
	err = tx.QueryRow(ctx, `SELECT resource_id::text FROM tasks WHERE id=$1::uuid AND host_id=$2::uuid AND status='RUNNING' FOR UPDATE`, taskID, hostID).Scan(&resourceID)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(result)
	if result.Success {
		_, err = tx.Exec(ctx, `UPDATE tasks SET status='SUCCEEDED',result=$1,completed_at=now(),updated_at=now() WHERE id=$2::uuid`, data, taskID)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE instances SET lifecycle_status='RUNNING',provider_status='RUNNING',provider_ref=$1,ip_address=nullif($2,'')::inet,updated_at=now() WHERE id=$3::uuid`, result.ProviderRef, result.IPAddress, resourceID)
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE ip_addresses SET status='ALLOCATED',allocated_at=now(),updated_at=now() WHERE instance_id=$1::uuid`, resourceID)
		}
	} else {
		_, err = tx.Exec(ctx, `UPDATE tasks SET status=CASE WHEN attempt>=max_attempts THEN 'FAILED' ELSE 'PENDING' END,error_message=$1,available_at=now()+interval '15 seconds',updated_at=now() WHERE id=$2::uuid`, result.Error, taskID)
		if err == nil {
			_, _ = tx.Exec(ctx, `UPDATE instances SET lifecycle_status='ERROR',updated_at=now() WHERE id=$1::uuid`, resourceID)
		}
	}
	if err != nil {
		return err
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
		}
	}
}
