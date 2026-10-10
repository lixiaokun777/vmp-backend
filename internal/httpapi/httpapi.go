package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"vmp-backend/internal/platform"
)

type API struct {
	Service               *platform.Service
	BootstrapToken        string
	SessionTTL            time.Duration
	SessionSecure         bool
	TrustedProxies        []netip.Prefix
	SettingsEncryptionKey []byte
	ConsoleSigningKey     []byte
	LDAP                  LDAPConfig
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	a.registerGovernanceRoutes(mux)
	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.HandleFunc("POST /api/v1/auth/login", a.authLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", a.authLogout)
	mux.HandleFunc("GET /api/v1/auth/me", a.authMe)
	mux.HandleFunc("POST /api/v1/auth/password", a.changeOwnPassword)
	mux.HandleFunc("GET /api/v1/users", a.users)
	mux.HandleFunc("POST /api/v1/users", a.createLocalUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}", a.updateUser)
	mux.HandleFunc("POST /api/v1/users/{id}/password", a.resetLocalUserPassword)
	mux.HandleFunc("DELETE /api/v1/users/{id}", a.deleteUser)
	mux.HandleFunc("GET /api/v1/ldap/status", a.ldapStatus)
	mux.HandleFunc("PUT /api/v1/ldap/config", a.updateLDAPConfig)
	mux.HandleFunc("POST /api/v1/ldap/test", a.ldapTest)
	mux.HandleFunc("POST /api/v1/ldap/sync", a.ldapSync)
	mux.HandleFunc("GET /api/v1/notifications/config", a.notificationConfig)
	mux.HandleFunc("PUT /api/v1/notifications/config", a.updateNotificationConfig)
	mux.HandleFunc("POST /api/v1/notifications/test", a.testNotification)
	mux.HandleFunc("GET /api/v1/notifications/events", a.notificationEvents)
	mux.HandleFunc("GET /api/v1/summary", a.summary)
	mux.HandleFunc("GET /api/v1/hosts", a.hosts)
	mux.HandleFunc("PATCH /api/v1/hosts/{id}/status", a.hostStatus)
	mux.HandleFunc("PATCH /api/v1/hosts/{id}/quota", a.hostQuota)
	mux.HandleFunc("DELETE /api/v1/hosts/{id}", a.deleteHost)
	mux.HandleFunc("POST /api/v1/hosts/{id}/credentials/rotate", a.rotateHostCredential)
	mux.HandleFunc("POST /api/v1/hosts/{id}/credentials/revoke", a.revokeHostCredential)
	mux.HandleFunc("GET /api/v1/flavors", a.flavors)
	mux.HandleFunc("POST /api/v1/flavors", a.createFlavor)
	mux.HandleFunc("PATCH /api/v1/flavors/{id}", a.updateFlavor)
	mux.HandleFunc("DELETE /api/v1/flavors/{id}", a.deleteFlavor)
	mux.HandleFunc("GET /api/v1/images", a.images)
	mux.HandleFunc("POST /api/v1/images", a.createImage)
	mux.HandleFunc("PATCH /api/v1/images/{id}", a.updateImage)
	mux.HandleFunc("DELETE /api/v1/images/{id}", a.deleteImage)
	mux.HandleFunc("POST /api/v1/images/{id}/sync", a.syncImage)
	mux.HandleFunc("GET /api/v1/networks", a.networks)
	mux.HandleFunc("POST /api/v1/networks", a.createNetwork)
	mux.HandleFunc("PATCH /api/v1/networks/{id}", a.updateNetwork)
	mux.HandleFunc("DELETE /api/v1/networks/{id}", a.deleteNetwork)
	mux.HandleFunc("POST /api/v1/networks/{id}/ip-ranges", a.addIPRange)
	mux.HandleFunc("DELETE /api/v1/networks/{id}/ip-ranges", a.deleteIPRange)
	mux.HandleFunc("GET /api/v1/ip-addresses", a.ipAddresses)
	mux.HandleFunc("POST /api/v1/ip-addresses/{id}/probe", a.probeIPAddress)
	mux.HandleFunc("POST /api/v1/networks/{id}/probe-quarantined", a.probeQuarantinedNetwork)
	mux.HandleFunc("GET /api/v1/applications", a.applications)
	mux.HandleFunc("POST /api/v1/applications", a.createApplication)
	mux.HandleFunc("GET /api/v1/instances", a.instances)
	mux.HandleFunc("GET /api/v1/instances/{id}", a.instanceDetail)
	mux.HandleFunc("POST /api/v1/instances/{id}/actions", a.instanceAction)
	mux.HandleFunc("POST /api/v1/instances/{id}/renew", a.renewInstance)
	mux.HandleFunc("POST /api/v1/instances/{id}/restore", a.restoreInstance)
	mux.HandleFunc("POST /api/v1/instances/{id}/console-sessions", a.createConsoleSession)
	mux.HandleFunc("GET /api/v1/approvals", a.approvals)
	mux.HandleFunc("POST /api/v1/approvals/{id}/withdraw", a.withdrawApproval)
	mux.HandleFunc("POST /api/v1/approvals/{id}/resubmit-short", a.resubmitApprovalShort)
	mux.HandleFunc("POST /api/v1/approvals/{id}/decision", a.decideApproval)
	mux.HandleFunc("POST /api/v1/approvals/batch-decision", a.batchDecideApprovals)
	mux.HandleFunc("GET /api/v1/tasks", a.tasks)
	mux.HandleFunc("GET /api/v1/audit-logs", a.auditLogs)
	mux.HandleFunc("POST /api/v1/agents/register", a.registerAgent)
	mux.HandleFunc("GET /api/v1/agents/{id}/catalog", a.agentCatalog)
	mux.HandleFunc("POST /api/v1/agents/{id}/heartbeat", a.agentHeartbeat)
	mux.HandleFunc("POST /api/v1/agents/{id}/console-sessions/{sessionID}/consume", a.consumeConsoleSession)
	mux.HandleFunc("GET /api/v1/agents/{id}/tasks/next", a.agentTask)
	mux.HandleFunc("POST /api/v1/agents/{id}/tasks/{taskID}/result", a.agentTaskResult)
	mux.HandleFunc("POST /api/v1/agents/{id}/tasks/{taskID}/renew", a.renewAgentTaskLease)
	if a.SessionTTL <= 0 {
		a.SessionTTL = 12 * time.Hour
	}
	return withMiddleware(a.authenticate(a.auditMutation(mux)))
}

func withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 总量上限覆盖 Agent 清单等大 JSON，登录和配置接口可继续使用更小上限。
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Info("request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	if err := a.Service.DB.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "vm-lease-control-plane", "time": time.Now()})
}

func (a *API) summary(w http.ResponseWriter, r *http.Request) {
	row := a.Service.DB.QueryRow(r.Context(), `SELECT
		(SELECT count(*) FROM hosts WHERE status='ACTIVE' AND agent_mode<>'mock'),
		(SELECT count(*) FROM instances i JOIN hosts h ON h.id=i.host_id WHERE i.lifecycle_status='RUNNING' AND h.agent_mode<>'mock'),
		(SELECT count(*) FROM instances i JOIN hosts h ON h.id=i.host_id WHERE i.lifecycle_status='PROVISIONING' AND h.agent_mode<>'mock'),
		(SELECT count(*) FROM applications a JOIN instances i ON i.application_id=a.id JOIN hosts h ON h.id=i.host_id WHERE h.agent_mode<>'mock'),
		coalesce((SELECT sum(reserved_memory_mb) FROM hosts WHERE status='ACTIVE' AND agent_mode<>'mock'),0),
		coalesce((SELECT sum(allocatable_memory_mb) FROM hosts WHERE status='ACTIVE' AND agent_mode<>'mock'),0),
		(SELECT count(*) FROM approval_requests WHERE status='PENDING' AND expires_at>now())`)
	var h, running, provisioning, apps, usedMem, totalMem, pendingApprovals int
	if err := row.Scan(&h, &running, &provisioning, &apps, &usedMem, &totalMem, &pendingApprovals); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"active_hosts": h, "running_instances": running, "provisioning_instances": provisioning, "applications": apps, "reserved_memory_mb": usedMem, "allocatable_memory_mb": totalMem, "pending_approvals": pendingApprovals})
}

func (a *API) hosts(w http.ResponseWriter, r *http.Request) {
	filter := " WHERE h.agent_mode<>'mock'"
	if r.URL.Query().Get("all") == "1" {
		filter = ""
	}
	// 仅向管理员提供凭据状态和代次；列表绝不返回运行令牌或其摘要。
	a.queryList(w, r, `SELECT jsonb_build_object('id',h.id,'name',h.name,'provider_type',h.provider_type,'agent_mode',h.agent_mode,'status',h.status,'management_ip',h.management_ip,'allocatable_cpu',h.allocatable_cpu,'allocatable_memory_mb',h.allocatable_memory_mb,'allocatable_disk_gb',h.allocatable_disk_gb,'agent_allocatable_cpu',h.agent_allocatable_cpu,'agent_allocatable_memory_mb',h.agent_allocatable_memory_mb,'agent_allocatable_disk_gb',h.agent_allocatable_disk_gb,'quota_cpu',h.quota_cpu,'quota_memory_mb',h.quota_memory_mb,'quota_disk_gb',h.quota_disk_gb,'reserved_cpu',h.reserved_cpu,'reserved_memory_mb',h.reserved_memory_mb,'reserved_disk_gb',h.reserved_disk_gb,'last_heartbeat_at',h.last_heartbeat_at,'last_inventory_at',h.last_inventory_at,'facts',h.facts,'discovered_instances',(SELECT count(*) FROM discovered_instances d WHERE d.host_id=h.id),'external_instances',(SELECT count(*) FROM discovered_instances d WHERE d.host_id=h.id AND d.ownership='EXTERNAL'),'budget_source',h.budget_source,'safe_available_memory_mb',h.safe_available_memory_mb,'safe_available_disk_gb',h.safe_available_disk_gb,'resource_measured_at',h.resource_measured_at,'credential_status',CASE WHEN c.host_id IS NULL THEN 'MISSING' WHEN c.revoked_at IS NOT NULL THEN 'REVOKED' ELSE 'ACTIVE' END,'credential_generation',coalesce(c.generation,0),'credential_updated_at',c.updated_at) FROM hosts h LEFT JOIN host_credentials c ON c.host_id=h.id`+filter+` ORDER BY h.name`)
}
func (a *API) flavors(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	filter := " WHERE f.enabled"
	if user.Role == "ADMIN" && r.URL.Query().Get("all") == "1" {
		filter = ""
	}
	if user.Role != "ADMIN" {
		a.queryList(w, r, `SELECT jsonb_build_object('id',f.id,'name',f.name,'cpu',f.cpu,'memory_mb',f.memory_mb,'disk_gb',f.disk_gb,'enabled',f.enabled) FROM flavors f`+filter+` ORDER BY f.cpu,f.id`)
		return
	}
	a.queryList(w, r, `SELECT jsonb_build_object('id',f.id,'name',f.name,'cpu',f.cpu,'memory_mb',f.memory_mb,'disk_gb',f.disk_gb,'enabled',f.enabled,'usage',(SELECT jsonb_build_object('running',count(*) FILTER(WHERE i.lifecycle_status='RUNNING'),'retained',count(*) FILTER(WHERE i.lifecycle_status='RETAINED'),'active',count(*),'memory_mb',coalesce(sum(i.allocated_memory_mb),0),'disk_gb',coalesce(sum(i.allocated_disk_gb),0),'percent',coalesce(round(100.0*sum(i.allocated_memory_mb)/nullif((SELECT sum(h.allocatable_memory_mb) FROM hosts h WHERE h.agent_mode<>'mock'),0),2),0)) FROM instances i JOIN applications ap ON ap.id=i.application_id WHERE ap.flavor_id=f.id AND i.lifecycle_status<>'RELEASED')) FROM flavors f`+filter+` ORDER BY f.cpu,f.id`)
}
func (a *API) images(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	if user.Role != "ADMIN" {
		a.queryList(w, r, `SELECT jsonb_build_object('id',id,'name',name,'os_family',os_family,'version',version) FROM images WHERE enabled AND sync_status='READY' ORDER BY name`)
		return
	}
	filter := " WHERE enabled"
	if r.URL.Query().Get("all") == "1" {
		filter = ""
	}
	a.queryList(w, r, `SELECT jsonb_build_object('id',images.id,'name',name,'file_name',file_name,'source_type',source_type,'source_location',source_location,'checksum',checksum,'sync_status',sync_status,'os_family',os_family,'version',version,'enabled',enabled,'desired_enabled',desired_enabled,'generation',generation,'host_readiness',coalesce((SELECT jsonb_agg(jsonb_build_object('host_id',hi.host_id,'host_name',h.name,'status',CASE WHEN hi.generation<>images.generation OR hi.reported_at<now()-interval '120 seconds' THEN 'STALE' ELSE hi.status END,'error',hi.error,'verified_at',hi.verified_at,'generation',hi.generation) ORDER BY h.name) FROM host_images hi JOIN hosts h ON h.id=hi.host_id WHERE hi.image_id=images.id),'[]'::jsonb)) FROM images`+filter+` ORDER BY name,id`)
}
func (a *API) applications(w http.ResponseWriter, r *http.Request) {
	a.queryList(w, r, `SELECT jsonb_build_object('id',a.id,'request_no',a.request_no,'applicant',a.applicant,'instance_name',a.instance_name,'purpose',a.purpose,'flavor',f.name,'image',i.name,'lease_hours',a.lease_hours,'status',a.status,'created_at',a.created_at) FROM applications a JOIN flavors f ON f.id=a.flavor_id JOIN images i ON i.id=a.image_id ORDER BY a.created_at DESC`)
}
func (a *API) instances(w http.ResponseWriter, r *http.Request) {
	a.instancesPage(w, r)
}

func (a *API) instanceDetail(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	var instance json.RawMessage
	err := a.Service.DB.QueryRow(r.Context(), `SELECT jsonb_build_object('id',i.id,'name',i.name,'owner',a.applicant,'purpose',a.purpose,'request_no',a.request_no,'host',h.name,'host_id',i.host_id,'flavor_id',a.flavor_id,'resource_snapshot',jsonb_build_object('cpu',i.allocated_cpu,'memory_mb',i.allocated_memory_mb,'disk_gb',i.allocated_disk_gb),'flavor',jsonb_build_object('id',f.id,'name',i.flavor_name_snapshot,'cpu',i.allocated_cpu,'memory_mb',i.allocated_memory_mb,'disk_gb',i.allocated_disk_gb),'image',jsonb_build_object('id',im.id,'name',im.name,'source_type',im.source_type,'source_location',im.source_location,'sync_status',im.sync_status),'lifecycle_status',i.lifecycle_status,'provider_status',i.provider_status,'provider_ref',i.provider_ref,'ip_address',i.ip_address,'username',i.username,'expires_at',i.expires_at,'retention_until',i.retention_until,'restore_count',i.restore_count,'created_at',i.created_at,'updated_at',i.updated_at) FROM instances i JOIN applications a ON a.id=i.application_id JOIN flavors f ON f.id=a.flavor_id JOIN images im ON im.id=a.image_id LEFT JOIN hosts h ON h.id=i.host_id WHERE i.id=$1::uuid AND ($3 OR a.applicant=$2)`, r.PathValue("id"), user.Username, user.Role == "ADMIN").Scan(&instance)
	if err != nil {
		writeError(w, 404, "instance not found")
		return
	}
	var extra json.RawMessage
	err = a.Service.DB.QueryRow(r.Context(), `SELECT jsonb_build_object('delivery_status',i.delivery_status,'delivery_message',i.delivery_message,'observed_domain_status',i.observed_domain_status,'last_domain_seen_at',i.last_domain_seen_at,'network_id',i.network_id,'ip_recovery_pending',i.ip_recovery_pending,'ip_recovery_message',i.ip_recovery_message,'ip_recovery_task_id',i.ip_recovery_task_id,'console_available',i.expires_at>now() AND i.lifecycle_status IN ('RUNNING','PROVISIONING','ERROR','STOPPED') AND EXISTS(SELECT 1 FROM discovered_instances d WHERE d.host_id=i.host_id AND d.platform_instance_id=i.id AND d.name=i.name AND d.ownership='MANAGED' AND (i.provider_ref IS NULL OR i.provider_ref=d.provider_uuid) AND d.last_seen_at>now()-interval '120 seconds' AND lower(replace(d.state,' ','_')) IN ('running','paused','blocked','pmsuspended'))) FROM instances i JOIN applications ap ON ap.id=i.application_id WHERE i.id=$1::uuid AND ($3 OR ap.applicant=$2)`, r.PathValue("id"), user.Username, user.Role == "ADMIN").Scan(&extra)
	if err != nil {
		writeError(w, 404, "实例已变化，请刷新")
		return
	}
	var fields, more map[string]any
	if json.Unmarshal(instance, &fields) != nil || json.Unmarshal(extra, &more) != nil {
		writeError(w, 500, "实例详情数据无效")
		return
	}
	for key, value := range more {
		fields[key] = value
	}
	if user.Role != "ADMIN" {
		if image, ok := fields["image"].(map[string]any); ok {
			delete(image, "source_location")
		}
	}
	instance, _ = json.Marshal(fields)
	tasks, err := queryRawList(r, a.Service.DB, `SELECT jsonb_build_object('id',id,'task_type',task_type,'status',status,'attempt',attempt,'max_attempts',max_attempts,'error_message',error_message,'created_at',created_at,'completed_at',completed_at) FROM tasks WHERE resource_id=$1::uuid OR (task_type='PROBE_IP_ADDRESS' AND payload->>'retry_instance_id'=($1::uuid)::text) ORDER BY created_at DESC`, r.PathValue("id"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	audits, err := queryRawList(r, a.Service.DB, `SELECT jsonb_build_object('action',action,'actor',actor,'detail',detail,'created_at',created_at) FROM audit_logs WHERE resource_type='instance' AND resource_id=($1::uuid)::text ORDER BY created_at DESC`, r.PathValue("id"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"instance": instance, "tasks": tasks, "audit_logs": audits})
}

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func queryRawList(r *http.Request, db queryer, sql string, args ...any) ([]json.RawMessage, error) {
	rows, err := db.Query(r.Context(), sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]json.RawMessage, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		items = append(items, raw)
	}
	return items, rows.Err()
}
func (a *API) tasks(w http.ResponseWriter, r *http.Request) {
	a.queryList(w, r, `SELECT jsonb_build_object('id',id,'task_type',task_type,'status',status,'attempt',attempt,'error_message',error_message,'created_at',created_at,'completed_at',completed_at) FROM tasks ORDER BY created_at DESC LIMIT 100`)
}

func (a *API) queryList(w http.ResponseWriter, r *http.Request, sql string) {
	a.queryListArgs(w, r, sql)
}

func (a *API) queryListArgs(w http.ResponseWriter, r *http.Request, sql string, args ...any) {
	rows, err := a.Service.DB.Query(r.Context(), sql, args...)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	defer rows.Close()
	items := make([]json.RawMessage, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		items = append(items, raw)
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (a *API) networks(w http.ResponseWriter, r *http.Request) {
	a.queryList(w, r, `SELECT jsonb_build_object('id',n.id,'name',n.name,'cidr',n.cidr,'gateway',n.gateway,'dns_servers',n.dns_servers,'bridge',n.bridge,'enabled',n.enabled,'ip_range_start',(array_agg(host(ip.address) ORDER BY ip.address) FILTER(WHERE ip.id IS NOT NULL))[1],'ip_range_end',(array_agg(host(ip.address) ORDER BY ip.address DESC) FILTER(WHERE ip.id IS NOT NULL))[1],'total',count(ip.id),'free',count(ip.id) FILTER(WHERE ip.status='FREE'),'reserved',count(ip.id) FILTER(WHERE ip.status='RESERVED'),'allocated',count(ip.id) FILTER(WHERE ip.status='ALLOCATED'),'quarantined',count(ip.id) FILTER(WHERE ip.status='QUARANTINED')) FROM networks n LEFT JOIN ip_addresses ip ON ip.network_id=n.id GROUP BY n.id ORDER BY n.name`)
}

type networkInput struct {
	Name       string   `json:"name"`
	CIDR       string   `json:"cidr"`
	Gateway    string   `json:"gateway"`
	DNSServers []string `json:"dns_servers"`
	Bridge     string   `json:"bridge"`
	Enabled    *bool    `json:"enabled"`
	RangeStart string   `json:"ip_range_start"`
	RangeEnd   string   `json:"ip_range_end"`
}

func validateNetworkInput(in networkInput) error {
	prefix, err := netip.ParsePrefix(in.CIDR)
	if err != nil || !prefix.Addr().Is4() || in.Name == "" || in.Bridge == "" {
		return errors.New("invalid IPv4 network")
	}
	gateway, err := netip.ParseAddr(in.Gateway)
	if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
		return errors.New("gateway must be inside the network")
	}
	for _, value := range in.DNSServers {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return errors.New("DNS server must be an IPv4 address")
		}
	}
	if _, err := networkRangeAddresses(in); err != nil {
		return err
	}
	return nil
}

// networkRangeAddresses 将管理员配置的唯一地址范围展开为可分配地址，并排除网关。
func networkRangeAddresses(in networkInput) ([]string, error) {
	start, startErr := netip.ParseAddr(in.RangeStart)
	end, endErr := netip.ParseAddr(in.RangeEnd)
	if startErr != nil || endErr != nil || !start.Is4() || !end.Is4() || start.Compare(end) > 0 {
		return nil, errors.New("IP 地址范围无效")
	}
	prefix, _ := netip.ParsePrefix(in.CIDR)
	gateway, _ := netip.ParseAddr(in.Gateway)
	addresses := make([]string, 0)
	for current := start; ; current = current.Next() {
		if !prefix.Contains(current) {
			return nil, errors.New("IP 地址范围必须完全位于网络 CIDR 内")
		}
		if current != gateway {
			addresses = append(addresses, current.String())
		}
		if current == end {
			break
		}
		if len(addresses) >= 4096 {
			return nil, errors.New("IP 地址范围不能超过 4096 个地址")
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("IP 地址范围中没有可分配地址")
	}
	return addresses, nil
}

func (a *API) createNetwork(w http.ResponseWriter, r *http.Request) {
	var in networkInput
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	if err := validateNetworkInput(in); err != nil {
		writeError(w, 422, err.Error())
		return
	}
	addresses, _ := networkRangeAddresses(in)
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	var id string
	err = tx.QueryRow(r.Context(), `INSERT INTO networks(name,cidr,gateway,dns_servers,bridge,enabled) VALUES($1,$2::cidr,$3::inet,$4,$5,coalesce($6,true)) RETURNING id::text`, in.Name, in.CIDR, in.Gateway, in.DNSServers, in.Bridge, in.Enabled).Scan(&id)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO ip_addresses(network_id,address) SELECT $1::uuid,value::inet FROM unnest($2::text[]) value`, id, addresses); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "ip_range_start": in.RangeStart, "ip_range_end": in.RangeEnd, "total": len(addresses)})
}

func (a *API) updateNetwork(w http.ResponseWriter, r *http.Request) {
	var in networkInput
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Enabled == nil {
		writeError(w, 400, "invalid JSON or missing enabled")
		return
	}
	if err := validateNetworkInput(in); err != nil {
		writeError(w, 422, err.Error())
		return
	}
	addresses, _ := networkRangeAddresses(in)
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	var existingID string
	if err := tx.QueryRow(r.Context(), `SELECT id::text FROM networks WHERE id=$1::uuid FOR UPDATE`, r.PathValue("id")).Scan(&existingID); err != nil {
		writeError(w, 404, "网络不存在")
		return
	}
	rows, err := tx.Query(r.Context(), `SELECT id FROM ip_addresses WHERE network_id=$1::uuid FOR UPDATE`, existingID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	for rows.Next() {
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	var occupiedOutside int
	if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM ip_addresses WHERE network_id=$1::uuid AND status<>'FREE' AND (NOT (address BETWEEN $2::inet AND $3::inet) OR address=$4::inet)`, existingID, in.RangeStart, in.RangeEnd, in.Gateway).Scan(&occupiedOutside); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if occupiedOutside > 0 {
		writeError(w, 409, "新范围之外仍有已分配、预留或隔离的 IP，不能替换地址池")
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM ip_addresses WHERE network_id=$1::uuid AND status='FREE' AND (NOT (address BETWEEN $2::inet AND $3::inet) OR address=$4::inet)`, existingID, in.RangeStart, in.RangeEnd, in.Gateway); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO ip_addresses(network_id,address) SELECT $1::uuid,value::inet FROM unnest($2::text[]) value ON CONFLICT(address) DO NOTHING`, existingID, addresses); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	var actualRangeSize int
	if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM ip_addresses WHERE network_id=$1::uuid AND address BETWEEN $2::inet AND $3::inet`, existingID, in.RangeStart, in.RangeEnd).Scan(&actualRangeSize); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if actualRangeSize != len(addresses) {
		writeError(w, 409, "IP 范围与其他网络的地址池冲突")
		return
	}
	tag, err := tx.Exec(r.Context(), `UPDATE networks SET name=$1,cidr=$2::cidr,gateway=$3::inet,dns_servers=$4,bridge=$5,enabled=$6,updated_at=now() WHERE id=$7::uuid`, in.Name, in.CIDR, in.Gateway, in.DNSServers, in.Bridge, *in.Enabled, existingID)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 404, "network not found")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": existingID, "updated": true, "ip_range_start": in.RangeStart, "ip_range_end": in.RangeEnd, "total": len(addresses)})
}

func (a *API) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	var name string
	if err := tx.QueryRow(r.Context(), `SELECT name FROM networks WHERE id=$1::uuid FOR UPDATE`, r.PathValue("id")).Scan(&name); err != nil {
		writeError(w, 404, "网络不存在")
		return
	}
	var occupied int
	if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM ip_addresses WHERE network_id=$1::uuid AND status<>'FREE'`, r.PathValue("id")).Scan(&occupied); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if occupied > 0 {
		writeError(w, 409, "网络中仍有已分配、预留或隔离的 IP，不能删除")
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM ip_addresses WHERE network_id=$1::uuid`, r.PathValue("id")); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM networks WHERE id=$1::uuid`, r.PathValue("id")); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": r.PathValue("id"), "name": name, "deleted": true})
}

func (a *API) addIPRange(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Start string `json:"start"`
		End   string `json:"end"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	start, startErr := netip.ParseAddr(in.Start)
	end, endErr := netip.ParseAddr(in.End)
	if startErr != nil || endErr != nil || !start.Is4() || !end.Is4() || start.Compare(end) > 0 {
		writeError(w, 422, "invalid IPv4 range")
		return
	}
	var cidr, gateway string
	if err := a.Service.DB.QueryRow(r.Context(), `SELECT cidr::text,host(gateway) FROM networks WHERE id=$1::uuid`, r.PathValue("id")).Scan(&cidr, &gateway); err != nil {
		writeError(w, 404, "network not found")
		return
	}
	prefix, _ := netip.ParsePrefix(cidr)
	addresses := make([]string, 0)
	for current := start; ; current = current.Next() {
		if !prefix.Contains(current) {
			writeError(w, 422, "IP range must be inside the network")
			return
		}
		if current.String() != gateway {
			addresses = append(addresses, current.String())
		}
		if current == end {
			break
		}
		if len(addresses) >= 4096 {
			writeError(w, 422, "IP range is too large")
			return
		}
	}
	if len(addresses) == 0 {
		writeError(w, 422, "IP range contains no allocatable address")
		return
	}
	tag, err := a.Service.DB.Exec(r.Context(), `INSERT INTO ip_addresses(network_id,address) SELECT $1::uuid,value::inet FROM unnest($2::text[]) value ON CONFLICT(address) DO NOTHING`, r.PathValue("id"), addresses)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"inserted": tag.RowsAffected(), "probe_policy": "Agent allocates only after an ICMP occupancy probe"})
}

func (a *API) deleteIPRange(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Start string `json:"start"`
		End   string `json:"end"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeError(w, 400, "JSON 格式无效")
		return
	}
	start, startErr := netip.ParseAddr(in.Start)
	end, endErr := netip.ParseAddr(in.End)
	if startErr != nil || endErr != nil || !start.Is4() || !end.Is4() || start.Compare(end) > 0 {
		writeError(w, 422, "IPv4 地址范围无效")
		return
	}
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	var cidr string
	if err := tx.QueryRow(r.Context(), `SELECT cidr::text FROM networks WHERE id=$1::uuid FOR UPDATE`, r.PathValue("id")).Scan(&cidr); err != nil {
		writeError(w, 404, "网络不存在")
		return
	}
	prefix, _ := netip.ParsePrefix(cidr)
	if !prefix.Contains(start) || !prefix.Contains(end) {
		writeError(w, 422, "IP 地址范围必须位于网络 CIDR 内")
		return
	}
	rows, err := tx.Query(r.Context(), `SELECT status FROM ip_addresses WHERE network_id=$1::uuid AND address BETWEEN $2::inet AND $3::inet FOR UPDATE`, r.PathValue("id"), in.Start, in.End)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	count := 0
	occupied := false
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			rows.Close()
			writeError(w, 500, err.Error())
			return
		}
		count++
		occupied = occupied || status != "FREE"
	}
	rows.Close()
	if occupied {
		writeError(w, 409, "范围中包含已分配、预留或隔离的 IP，不能删除")
		return
	}
	if count == 0 {
		writeError(w, 404, "指定范围中没有可删除的 IP")
		return
	}
	tag, err := tx.Exec(r.Context(), `DELETE FROM ip_addresses WHERE network_id=$1::uuid AND address BETWEEN $2::inet AND $3::inet`, r.PathValue("id"), in.Start, in.End)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": tag.RowsAffected()})
}

func (a *API) ipAddresses(w http.ResponseWriter, r *http.Request) {
	a.ipAddressesPage(w, r)
}

func (a *API) hostStatus(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	if in.Status != "ACTIVE" && in.Status != "CORDONED" && in.Status != "MAINTENANCE" {
		writeError(w, 422, "unsupported host status")
		return
	}
	tag, err := a.Service.DB.Exec(r.Context(), `UPDATE hosts h SET status=$1,updated_at=now() WHERE id=$2::uuid AND ($1<>'ACTIVE' OR EXISTS(SELECT 1 FROM host_credentials c WHERE c.host_id=h.id AND c.revoked_at IS NULL AND h.last_heartbeat_at>=c.updated_at))`, in.Status, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 422, "宿主机不存在，或独立凭据未就绪；重新签发后需确认新 Agent 心跳才能恢复调度")
		return
	}
	writeJSON(w, 200, map[string]any{"status": in.Status})
}

func (a *API) hostQuota(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CPU      int `json:"cpu"`
		MemoryMB int `json:"memory_mb"`
		DiskGB   int `json:"disk_gb"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.CPU < 0 || in.MemoryMB < 0 || in.DiskGB < 0 {
		writeError(w, 422, "invalid host quota")
		return
	}
	tag, err := a.Service.DB.Exec(r.Context(), `UPDATE hosts SET quota_cpu=$1,quota_memory_mb=$2,quota_disk_gb=$3,allocatable_cpu=$1,allocatable_memory_mb=$2,allocatable_disk_gb=$3,updated_at=now() WHERE id=$4::uuid AND $1 BETWEEN reserved_cpu AND agent_allocatable_cpu AND $2 BETWEEN reserved_memory_mb AND agent_allocatable_memory_mb AND $3 BETWEEN reserved_disk_gb AND agent_allocatable_disk_gb`, in.CPU, in.MemoryMB, in.DiskGB, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 422, "quota exceeds the Agent limit, is below reserved resources, or host was not found")
		return
	}
	writeJSON(w, 200, map[string]any{"cpu": in.CPU, "memory_mb": in.MemoryMB, "disk_gb": in.DiskGB})
}

func (a *API) deleteHost(w http.ResponseWriter, r *http.Request) {
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	var name, status string
	if err := tx.QueryRow(r.Context(), `SELECT name,status FROM hosts WHERE id=$1::uuid FOR UPDATE`, r.PathValue("id")).Scan(&name, &status); err != nil {
		writeError(w, 404, "宿主机不存在")
		return
	}
	if status != "OFFLINE" {
		writeError(w, 409, "必须先停止 Agent 并等待宿主机变为 OFFLINE，才能删除纳管记录")
		return
	}
	var activeInstances, activeTasks int
	if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM instances WHERE host_id=$1::uuid AND lifecycle_status<>'RELEASED'`, r.PathValue("id")).Scan(&activeInstances); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM tasks WHERE host_id=$1::uuid AND status IN ('PENDING','RUNNING')`, r.PathValue("id")).Scan(&activeTasks); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if activeInstances > 0 || activeTasks > 0 {
		writeError(w, 409, "宿主机仍有关联实例或待执行任务，不能删除")
		return
	}
	if _, err := tx.Exec(r.Context(), `UPDATE instances SET host_id=NULL WHERE host_id=$1::uuid`, r.PathValue("id")); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `UPDATE tasks SET host_id=NULL WHERE host_id=$1::uuid`, r.PathValue("id")); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM hosts WHERE id=$1::uuid`, r.PathValue("id")); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": r.PathValue("id"), "name": name, "deleted": true})
}

type flavorInput struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	CPU      int    `json:"cpu"`
	MemoryMB int    `json:"memory_mb"`
	DiskGB   int    `json:"disk_gb"`
	Enabled  *bool  `json:"enabled"`
}

func (a *API) createFlavor(w http.ResponseWriter, r *http.Request) {
	var in flavorInput
	if json.NewDecoder(r.Body).Decode(&in) != nil || !resourceIdentifierPattern.MatchString(in.ID) || in.Name == "" || in.CPU < 1 || in.MemoryMB < 512 || in.DiskGB < 10 {
		writeError(w, 422, "规格信息无效；标识仅支持字母、数字、点、下划线和连字符，最多 64 字符")
		return
	}
	_, err := a.Service.DB.Exec(r.Context(), `INSERT INTO flavors(id,name,cpu,memory_mb,disk_gb) VALUES($1,$2,$3,$4,$5)`, in.ID, in.Name, in.CPU, in.MemoryMB, in.DiskGB)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": in.ID})
}
func (a *API) updateFlavor(w http.ResponseWriter, r *http.Request) {
	var in flavorInput
	if !resourceIdentifierPattern.MatchString(r.PathValue("id")) || json.NewDecoder(r.Body).Decode(&in) != nil || in.Enabled == nil || in.Name == "" || in.CPU < 1 || in.MemoryMB < 512 || in.DiskGB < 10 {
		writeError(w, 422, "规格标识或资源信息无效；需要名称、CPU、内存、磁盘和启用状态")
		return
	}
	_, err := a.Service.DB.Exec(r.Context(), `UPDATE flavors SET name=$1,cpu=$2,memory_mb=$3,disk_gb=$4,enabled=$5 WHERE id=$6`, in.Name, in.CPU, in.MemoryMB, in.DiskGB, *in.Enabled, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": *in.Enabled})
}

func (a *API) deleteFlavor(w http.ResponseWriter, r *http.Request) {
	if !resourceIdentifierPattern.MatchString(r.PathValue("id")) {
		writeError(w, 422, "规格标识仅支持字母、数字、点、下划线和连字符，最多 64 字符")
		return
	}
	tag, err := a.Service.DB.Exec(r.Context(), `DELETE FROM flavors f WHERE f.id=$1 AND NOT EXISTS (SELECT 1 FROM applications a WHERE a.flavor_id=f.id)`, r.PathValue("id"))
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 409, "规格不存在或已被申请记录引用；已使用的规格只能停用")
		return
	}
	writeJSON(w, 200, map[string]any{"id": r.PathValue("id"), "deleted": true})
}

type imageInput struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	FileName       string `json:"file_name"`
	SourceType     string `json:"source_type"`
	SourceLocation string `json:"source_location"`
	Checksum       string `json:"checksum"`
	OSFamily       string `json:"os_family"`
	Version        string `json:"version"`
	Enabled        *bool  `json:"enabled"`
}

var imageFileNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var resourceIdentifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func (a *API) createImage(w http.ResponseWriter, r *http.Request) {
	var in imageInput
	if json.NewDecoder(r.Body).Decode(&in) != nil || !resourceIdentifierPattern.MatchString(in.ID) || in.Name == "" || in.OSFamily == "" || in.Version == "" {
		writeError(w, 422, "镜像信息无效；标识仅支持字母、数字、点、下划线和连字符，最多 64 字符")
		return
	}
	if in.SourceType == "" {
		in.SourceType = "local"
	}
	syncStatus := "READY"
	desired := true
	if in.Enabled != nil {
		desired = *in.Enabled
	}
	enabled := desired
	if in.SourceType == "local" {
		if !imageFileNamePattern.MatchString(in.FileName) {
			writeError(w, 422, "local image requires a safe file_name")
			return
		}
		if in.SourceLocation == "" {
			in.SourceLocation = in.FileName
		}
	} else if in.SourceType == "remote" {
		remoteURL, err := url.ParseRequestURI(in.SourceLocation)
		if err != nil || remoteURL.Scheme != "https" || remoteURL.Host == "" || remoteURL.User != nil || !regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(in.Checksum) {
			writeError(w, 422, "远程镜像需要HTTPS地址和SHA-256摘要；禁止地址中嵌入用户名密码")
			return
		}
		if in.FileName == "" {
			in.FileName = in.ID + ".qcow2"
		}
		if !imageFileNamePattern.MatchString(in.FileName) {
			writeError(w, 422, "remote image cache file_name is invalid")
			return
		}
		syncStatus = "PENDING"
		enabled = false
	} else {
		writeError(w, 422, "source_type must be local or remote")
		return
	}
	_, err := a.Service.DB.Exec(r.Context(), `INSERT INTO images(id,name,file_name,source_type,source_location,checksum,sync_status,os_family,version,enabled,desired_enabled) VALUES($1,$2,$3,$4,$5,nullif($6,''),$7,$8,$9,$10,$11)`, in.ID, in.Name, in.FileName, in.SourceType, in.SourceLocation, strings.ToLower(in.Checksum), syncStatus, in.OSFamily, in.Version, enabled, desired)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": in.ID})
}
func (a *API) updateImage(w http.ResponseWriter, r *http.Request) {
	if !resourceIdentifierPattern.MatchString(r.PathValue("id")) {
		writeError(w, 422, "镜像标识仅支持字母、数字、点、下划线和连字符，最多 64 字符")
		return
	}
	var in imageInput
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Enabled == nil {
		writeError(w, 422, "enabled is required")
		return
	}
	if in.Name != "" {
		if in.OSFamily == "" || in.Version == "" || !imageFileNamePattern.MatchString(in.FileName) {
			writeError(w, 422, "name, safe file_name, os_family and version are required")
			return
		}
		syncStatus := "READY"
		enabled := *in.Enabled
		if in.SourceType == "local" {
			if in.SourceLocation == "" {
				in.SourceLocation = in.FileName
			}
			in.Checksum = ""
		} else if in.SourceType == "remote" {
			remoteURL, err := url.ParseRequestURI(in.SourceLocation)
			if err != nil || remoteURL.Scheme != "https" || remoteURL.Host == "" || remoteURL.User != nil || !regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(in.Checksum) {
				writeError(w, 422, "远程镜像需要HTTPS地址和SHA-256摘要；禁止地址中嵌入用户名密码")
				return
			}
			syncStatus = "PENDING"
			enabled = false
		} else {
			writeError(w, 422, "source_type must be local or remote")
			return
		}
		tx, err := a.Service.DB.Begin(r.Context())
		if err != nil {
			writeError(w, 503, "镜像管理暂不可用")
			return
		}
		defer tx.Rollback(r.Context())
		if err := platform.LockResourceReadiness(r.Context(), tx); err != nil {
			writeError(w, 503, "镜像就绪服务暂不可用")
			return
		}
		var oldFile, oldType, oldLocation, oldChecksum string
		if err := tx.QueryRow(r.Context(), `SELECT file_name,source_type,coalesce(source_location,''),coalesce(checksum,'') FROM images WHERE id=$1 FOR UPDATE`, r.PathValue("id")).Scan(&oldFile, &oldType, &oldLocation, &oldChecksum); err != nil {
			writeError(w, 404, "镜像不存在")
			return
		}
		changed := oldFile != in.FileName || oldType != in.SourceType || oldLocation != in.SourceLocation || !strings.EqualFold(oldChecksum, in.Checksum)
		tag, err := tx.Exec(r.Context(), `UPDATE images SET name=$1,file_name=$2,source_type=$3,source_location=$4,checksum=nullif($5,''),sync_status=CASE WHEN $11 THEN $6 ELSE sync_status END,os_family=$7,version=$8,enabled=$9,desired_enabled=$12,generation=generation+CASE WHEN $11 THEN 1 ELSE 0 END WHERE id=$10`, in.Name, in.FileName, in.SourceType, in.SourceLocation, strings.ToLower(in.Checksum), syncStatus, in.OSFamily, in.Version, enabled, r.PathValue("id"), changed, *in.Enabled)
		if err != nil {
			writeError(w, 422, err.Error())
			return
		}
		if tag.RowsAffected() == 0 {
			writeError(w, 404, "image was not found")
			return
		}
		if changed {
			if _, err := tx.Exec(r.Context(), `UPDATE host_images SET status='STALE',error='镜像定义已变更，需要重新同步或探测',verified_at=NULL WHERE image_id=$1`, r.PathValue("id")); err != nil {
				writeError(w, 500, "镜像就绪记录更新失败")
				return
			}
		}
		if _, err := tx.Exec(r.Context(), `UPDATE images SET enabled=desired_enabled AND (source_type='local' OR sync_status='READY') WHERE id=$1`, r.PathValue("id")); err != nil {
			writeError(w, 500, "保存镜像状态失败")
			return
		}
		if err := tx.QueryRow(r.Context(), `SELECT enabled,sync_status FROM images WHERE id=$1`, r.PathValue("id")).Scan(&enabled, &syncStatus); err != nil {
			writeError(w, 500, "读取镜像更新结果失败")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeError(w, 503, "镜像更新未完成，请重试")
			return
		}
		writeJSON(w, 200, map[string]any{"enabled": enabled, "sync_status": syncStatus, "definition_changed": changed})
		return
	}
	tag, err := a.Service.DB.Exec(r.Context(), `UPDATE images SET desired_enabled=$1,enabled=$1 AND (source_type='local' OR sync_status='READY') WHERE id=$2`, *in.Enabled, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 422, "image is not ready or was not found")
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": *in.Enabled})
}

func (a *API) deleteImage(w http.ResponseWriter, r *http.Request) {
	if !resourceIdentifierPattern.MatchString(r.PathValue("id")) {
		writeError(w, 422, "镜像标识仅支持字母、数字、点、下划线和连字符，最多 64 字符")
		return
	}
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 503, "镜像管理暂不可用")
		return
	}
	defer tx.Rollback(r.Context())
	if err := platform.LockResourceReadiness(r.Context(), tx); err != nil {
		writeError(w, 503, "镜像就绪服务暂不可用")
		return
	}
	tag, err := tx.Exec(r.Context(), `DELETE FROM images i WHERE i.id=$1 AND NOT EXISTS (SELECT 1 FROM applications a WHERE a.image_id=i.id)`, r.PathValue("id"))
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 409, "镜像不存在或已被申请记录引用；已使用的镜像只能停用")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, 503, "删除镜像未完成，请重试")
		return
	}
	writeJSON(w, 200, map[string]any{"id": r.PathValue("id"), "deleted": true})
}

func (a *API) createApplication(w http.ResponseWriter, r *http.Request) {
	var in platform.CreateApplicationInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	user, _ := userFromRequest(r)
	result, err := a.Service.CreateApplication(r.Context(), user.Username, in)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 201, result)
}

func (a *API) instanceAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	user, _ := userFromRequest(r)
	result, err := a.Service.PerformInstanceAction(r.Context(), user.Username, user.Role == "ADMIN", r.PathValue("id"), in.Action)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 202, result)
}

func (a *API) renewInstance(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hours  int    `json:"hours"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	user, _ := userFromRequest(r)
	result, err := a.Service.RenewInstance(r.Context(), user.Username, user.Role == "ADMIN", r.PathValue("id"), in.Hours, in.Reason)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

func (a *API) restoreInstance(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hours  int    `json:"hours"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	user, _ := userFromRequest(r)
	result, err := a.Service.RestoreInstance(r.Context(), user.Username, user.Role == "ADMIN", r.PathValue("id"), in.Hours, in.Reason)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

func (a *API) approvals(w http.ResponseWriter, r *http.Request) {
	a.approvalsPage(w, r)
}

func (a *API) decideApproval(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Decision      string `json:"decision"`
		Comment       string `json:"comment"`
		AdjustedHours int    `json:"adjusted_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	user, _ := userFromRequest(r)
	result, err := a.Service.DecideApproval(r.Context(), user.Username, r.PathValue("id"), in.Decision, in.Comment, in.AdjustedHours)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

func (a *API) withdrawApproval(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	if err := a.Service.WithdrawApproval(r.Context(), user.Username, r.PathValue("id")); err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": r.PathValue("id"), "status": "WITHDRAWN"})
}

func (a *API) resubmitApprovalShort(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hours  int    `json:"hours"`
		Reason string `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	user, _ := userFromRequest(r)
	result, err := a.Service.ResubmitApprovalShort(r.Context(), user.Username, user.Role == "ADMIN", r.PathValue("id"), in.Hours, in.Reason)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

func (a *API) batchDecideApprovals(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs      []string `json:"ids"`
		Decision string   `json:"decision"`
		Comment  string   `json:"comment"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || len(in.IDs) == 0 || len(in.IDs) > 50 {
		writeError(w, 422, "请选择 1-50 个审批单")
		return
	}
	user, _ := userFromRequest(r)
	items := make([]map[string]any, 0, len(in.IDs))
	for _, id := range in.IDs {
		result, err := a.Service.DecideApproval(r.Context(), user.Username, id, in.Decision, in.Comment, 0)
		if err != nil {
			items = append(items, map[string]any{"id": id, "success": false, "error": err.Error()})
		} else {
			items = append(items, map[string]any{"id": id, "success": true, "result": result})
		}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (a *API) registerAgent(w http.ResponseWriter, r *http.Request) {
	a.registerScopedAgent(w, r)
}

func (a *API) agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAgent(w, r) {
		return
	}
	var hb platform.Heartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	if err := a.Service.Heartbeat(r.Context(), r.PathValue("id"), hb); err != nil {
		writeError(w, 404, "host not found")
		return
	}
	writeJSON(w, 200, map[string]any{"accepted": true})
}

func (a *API) agentTask(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAgent(w, r) {
		return
	}
	task, err := a.Service.PollTask(r.Context(), r.PathValue("id"))
	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, task)
}

func (a *API) agentTaskResult(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAgent(w, r) {
		return
	}
	var result platform.TaskResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	if err := a.Service.CompleteTask(r.Context(), r.PathValue("id"), r.PathValue("taskID"), result); err != nil {
		if errors.Is(err, platform.ErrTaskClaimConflict) {
			writeError(w, 409, "任务领取凭据已失效或与当前执行不匹配")
		} else {
			writeError(w, 500, "任务结果保存失败，请重试")
		}
		return
	}
	writeJSON(w, 200, map[string]any{"accepted": true})
}

func (a *API) renewAgentTaskLease(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAgent(w, r) {
		return
	}
	var input struct {
		ClaimToken string `json:"claim_token"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input) != nil || input.ClaimToken == "" {
		writeError(w, 422, "任务领取凭据无效")
		return
	}
	until, err := a.Service.RenewTaskLease(r.Context(), r.PathValue("id"), r.PathValue("taskID"), input.ClaimToken)
	if err != nil {
		if errors.Is(err, platform.ErrTaskClaimConflict) {
			writeError(w, 409, "任务领取凭据已失效或与当前执行不匹配")
		} else {
			writeError(w, 500, "任务执行租约续期失败，请重试")
		}
		return
	}
	writeJSON(w, 200, map[string]any{"lease_until": until})
}

func tokenOK(r *http.Request, want, header string) bool {
	got := r.Header.Get(header)
	got = strings.TrimPrefix(got, "Bearer ")
	if want == "" {
		return false
	}
	gotHash, wantHash := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) == 1
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
