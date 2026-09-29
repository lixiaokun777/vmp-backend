package httpapi

import (
	"context"
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
	Service        *platform.Service
	BootstrapToken string
	AgentToken     string
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.HandleFunc("GET /api/v1/summary", a.summary)
	mux.HandleFunc("GET /api/v1/hosts", a.hosts)
	mux.HandleFunc("PATCH /api/v1/hosts/{id}/status", a.hostStatus)
	mux.HandleFunc("PATCH /api/v1/hosts/{id}/quota", a.hostQuota)
	mux.HandleFunc("GET /api/v1/flavors", a.flavors)
	mux.HandleFunc("POST /api/v1/flavors", a.createFlavor)
	mux.HandleFunc("PATCH /api/v1/flavors/{id}", a.updateFlavor)
	mux.HandleFunc("GET /api/v1/images", a.images)
	mux.HandleFunc("POST /api/v1/images", a.createImage)
	mux.HandleFunc("PATCH /api/v1/images/{id}", a.updateImage)
	mux.HandleFunc("GET /api/v1/networks", a.networks)
	mux.HandleFunc("POST /api/v1/networks", a.createNetwork)
	mux.HandleFunc("PATCH /api/v1/networks/{id}", a.updateNetwork)
	mux.HandleFunc("POST /api/v1/networks/{id}/ip-ranges", a.addIPRange)
	mux.HandleFunc("GET /api/v1/ip-addresses", a.ipAddresses)
	mux.HandleFunc("GET /api/v1/applications", a.applications)
	mux.HandleFunc("POST /api/v1/applications", a.createApplication)
	mux.HandleFunc("GET /api/v1/instances", a.instances)
	mux.HandleFunc("GET /api/v1/instances/{id}", a.instanceDetail)
	mux.HandleFunc("POST /api/v1/instances/{id}/actions", a.instanceAction)
	mux.HandleFunc("POST /api/v1/instances/{id}/renew", a.renewInstance)
	mux.HandleFunc("GET /api/v1/tasks", a.tasks)
	mux.HandleFunc("POST /api/v1/agents/register", a.registerAgent)
	mux.HandleFunc("POST /api/v1/agents/{id}/heartbeat", a.agentHeartbeat)
	mux.HandleFunc("GET /api/v1/agents/{id}/tasks/next", a.agentTask)
	mux.HandleFunc("POST /api/v1/agents/{id}/tasks/{taskID}/result", a.agentTaskResult)
	return withMiddleware(mux)
}

func withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		(SELECT count(*) FROM hosts WHERE status='ACTIVE'),
		(SELECT count(*) FROM instances WHERE lifecycle_status='RUNNING'),
		(SELECT count(*) FROM instances WHERE lifecycle_status='PROVISIONING'),
		(SELECT count(*) FROM applications),
		coalesce((SELECT sum(reserved_memory_mb) FROM hosts),0),
		coalesce((SELECT sum(allocatable_memory_mb) FROM hosts),0)`)
	var h, running, provisioning, apps, usedMem, totalMem int
	if err := row.Scan(&h, &running, &provisioning, &apps, &usedMem, &totalMem); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"active_hosts": h, "running_instances": running, "provisioning_instances": provisioning, "applications": apps, "reserved_memory_mb": usedMem, "allocatable_memory_mb": totalMem})
}

func (a *API) hosts(w http.ResponseWriter, r *http.Request) {
	a.queryList(w, r, `SELECT jsonb_build_object('id',h.id,'name',h.name,'provider_type',h.provider_type,'agent_mode',h.agent_mode,'status',h.status,'management_ip',h.management_ip,'allocatable_cpu',h.allocatable_cpu,'allocatable_memory_mb',h.allocatable_memory_mb,'allocatable_disk_gb',h.allocatable_disk_gb,'agent_allocatable_cpu',h.agent_allocatable_cpu,'agent_allocatable_memory_mb',h.agent_allocatable_memory_mb,'agent_allocatable_disk_gb',h.agent_allocatable_disk_gb,'quota_cpu',h.quota_cpu,'quota_memory_mb',h.quota_memory_mb,'quota_disk_gb',h.quota_disk_gb,'reserved_cpu',h.reserved_cpu,'reserved_memory_mb',h.reserved_memory_mb,'reserved_disk_gb',h.reserved_disk_gb,'last_heartbeat_at',h.last_heartbeat_at,'last_inventory_at',h.last_inventory_at,'facts',h.facts,'discovered_instances',(SELECT count(*) FROM discovered_instances d WHERE d.host_id=h.id),'external_instances',(SELECT count(*) FROM discovered_instances d WHERE d.host_id=h.id AND d.ownership='EXTERNAL')) FROM hosts h ORDER BY h.name`)
}
func (a *API) flavors(w http.ResponseWriter, r *http.Request) {
	filter := " WHERE enabled"
	if r.URL.Query().Get("all") == "1" {
		filter = ""
	}
	a.queryList(w, r, `SELECT jsonb_build_object('id',id,'name',name,'cpu',cpu,'memory_mb',memory_mb,'disk_gb',disk_gb,'enabled',enabled) FROM flavors`+filter+` ORDER BY cpu`)
}
func (a *API) images(w http.ResponseWriter, r *http.Request) {
	filter := " WHERE enabled"
	if r.URL.Query().Get("all") == "1" {
		filter = ""
	}
	a.queryList(w, r, `SELECT jsonb_build_object('id',id,'name',name,'file_name',file_name,'source_type',source_type,'source_location',source_location,'checksum',checksum,'sync_status',sync_status,'os_family',os_family,'version',version,'enabled',enabled) FROM images`+filter+` ORDER BY name`)
}
func (a *API) applications(w http.ResponseWriter, r *http.Request) {
	a.queryList(w, r, `SELECT jsonb_build_object('id',a.id,'request_no',a.request_no,'applicant',a.applicant,'instance_name',a.instance_name,'purpose',a.purpose,'flavor',f.name,'image',i.name,'lease_hours',a.lease_hours,'status',a.status,'created_at',a.created_at) FROM applications a JOIN flavors f ON f.id=a.flavor_id JOIN images i ON i.id=a.image_id ORDER BY a.created_at DESC`)
}
func (a *API) instances(w http.ResponseWriter, r *http.Request) {
	actor := r.Header.Get("X-User")
	if actor == "" {
		actor = "developer"
	}
	where := ""
	args := []any{}
	if r.URL.Query().Get("scope") == "mine" {
		where = " WHERE a.applicant=$1"
		args = append(args, actor)
	}
	a.queryListArgs(w, r, `SELECT jsonb_build_object('id',i.id,'name',i.name,'owner',a.applicant,'host',h.name,'flavor',f.name,'image',im.name,'lifecycle_status',i.lifecycle_status,'provider_status',i.provider_status,'ip_address',i.ip_address,'username',i.username,'expires_at',i.expires_at,'retention_until',i.retention_until,'created_at',i.created_at) FROM instances i JOIN applications a ON a.id=i.application_id JOIN flavors f ON f.id=a.flavor_id JOIN images im ON im.id=a.image_id LEFT JOIN hosts h ON h.id=i.host_id`+where+` ORDER BY i.created_at DESC`, args...)
}

func (a *API) instanceDetail(w http.ResponseWriter, r *http.Request) {
	actor := r.Header.Get("X-User")
	if actor == "" {
		actor = "developer"
	}
	var instance json.RawMessage
	err := a.Service.DB.QueryRow(r.Context(), `SELECT jsonb_build_object('id',i.id,'name',i.name,'owner',a.applicant,'purpose',a.purpose,'request_no',a.request_no,'host',h.name,'host_id',i.host_id,'flavor',jsonb_build_object('id',f.id,'name',f.name,'cpu',f.cpu,'memory_mb',f.memory_mb,'disk_gb',f.disk_gb),'image',jsonb_build_object('id',im.id,'name',im.name,'source_type',im.source_type,'source_location',im.source_location,'sync_status',im.sync_status),'lifecycle_status',i.lifecycle_status,'provider_status',i.provider_status,'provider_ref',i.provider_ref,'ip_address',i.ip_address,'username',i.username,'expires_at',i.expires_at,'retention_until',i.retention_until,'created_at',i.created_at,'updated_at',i.updated_at) FROM instances i JOIN applications a ON a.id=i.application_id JOIN flavors f ON f.id=a.flavor_id JOIN images im ON im.id=a.image_id LEFT JOIN hosts h ON h.id=i.host_id WHERE i.id=$1::uuid AND a.applicant=$2`, r.PathValue("id"), actor).Scan(&instance)
	if err != nil {
		writeError(w, 404, "instance not found")
		return
	}
	tasks, err := queryRawList(r, a.Service.DB, `SELECT jsonb_build_object('id',id,'task_type',task_type,'status',status,'attempt',attempt,'max_attempts',max_attempts,'error_message',error_message,'created_at',created_at,'completed_at',completed_at) FROM tasks WHERE resource_id=$1::uuid ORDER BY created_at DESC`, r.PathValue("id"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	audits, err := queryRawList(r, a.Service.DB, `SELECT jsonb_build_object('action',action,'actor',actor,'detail',detail,'created_at',created_at) FROM audit_logs WHERE resource_type='instance' AND resource_id=$1 ORDER BY created_at DESC`, r.PathValue("id"))
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
	a.queryList(w, r, `SELECT jsonb_build_object('id',n.id,'name',n.name,'cidr',n.cidr,'gateway',n.gateway,'dns_servers',n.dns_servers,'bridge',n.bridge,'enabled',n.enabled,'total',count(ip.id),'free',count(ip.id) FILTER(WHERE ip.status='FREE'),'reserved',count(ip.id) FILTER(WHERE ip.status='RESERVED'),'allocated',count(ip.id) FILTER(WHERE ip.status='ALLOCATED'),'quarantined',count(ip.id) FILTER(WHERE ip.status='QUARANTINED')) FROM networks n LEFT JOIN ip_addresses ip ON ip.network_id=n.id GROUP BY n.id ORDER BY n.name`)
}

type networkInput struct {
	Name       string   `json:"name"`
	CIDR       string   `json:"cidr"`
	Gateway    string   `json:"gateway"`
	DNSServers []string `json:"dns_servers"`
	Bridge     string   `json:"bridge"`
	Enabled    *bool    `json:"enabled"`
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
	return nil
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
	var id string
	err := a.Service.DB.QueryRow(r.Context(), `INSERT INTO networks(name,cidr,gateway,dns_servers,bridge,enabled) VALUES($1,$2::cidr,$3::inet,$4,$5,coalesce($6,true)) RETURNING id::text`, in.Name, in.CIDR, in.Gateway, in.DNSServers, in.Bridge, in.Enabled).Scan(&id)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
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
	tag, err := a.Service.DB.Exec(r.Context(), `UPDATE networks SET name=$1,cidr=$2::cidr,gateway=$3::inet,dns_servers=$4,bridge=$5,enabled=$6,updated_at=now() WHERE id=$7::uuid`, in.Name, in.CIDR, in.Gateway, in.DNSServers, in.Bridge, *in.Enabled, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 404, "network not found")
		return
	}
	writeJSON(w, 200, map[string]any{"id": r.PathValue("id"), "updated": true})
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

func (a *API) ipAddresses(w http.ResponseWriter, r *http.Request) {
	networkID := r.URL.Query().Get("network_id")
	if networkID == "" {
		writeError(w, 400, "network_id is required")
		return
	}
	a.queryListArgs(w, r, `SELECT jsonb_build_object('id',ip.id,'address',ip.address,'status',ip.status,'instance_id',ip.instance_id,'instance_name',i.name,'updated_at',ip.updated_at) FROM ip_addresses ip LEFT JOIN instances i ON i.id=ip.instance_id WHERE ip.network_id=$1::uuid ORDER BY ip.address LIMIT 512`, networkID)
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
	tag, err := a.Service.DB.Exec(r.Context(), `UPDATE hosts SET status=$1,updated_at=now() WHERE id=$2::uuid`, in.Status, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 404, "host not found")
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
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.ID == "" || in.Name == "" || in.CPU < 1 || in.MemoryMB < 512 || in.DiskGB < 10 {
		writeError(w, 422, "invalid flavor")
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
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Enabled == nil || in.Name == "" || in.CPU < 1 || in.MemoryMB < 512 || in.DiskGB < 10 {
		writeError(w, 422, "name, cpu, memory_mb, disk_gb and enabled are required")
		return
	}
	_, err := a.Service.DB.Exec(r.Context(), `UPDATE flavors SET name=$1,cpu=$2,memory_mb=$3,disk_gb=$4,enabled=$5 WHERE id=$6`, in.Name, in.CPU, in.MemoryMB, in.DiskGB, *in.Enabled, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": *in.Enabled})
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

func (a *API) createImage(w http.ResponseWriter, r *http.Request) {
	var in imageInput
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.ID == "" || in.Name == "" || in.OSFamily == "" || in.Version == "" {
		writeError(w, 422, "invalid image")
		return
	}
	if in.SourceType == "" {
		in.SourceType = "local"
	}
	syncStatus := "READY"
	enabled := true
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
		if err != nil || (remoteURL.Scheme != "http" && remoteURL.Scheme != "https") || remoteURL.Host == "" || !regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(in.Checksum) {
			writeError(w, 422, "remote image requires an HTTP(S) URL and SHA-256 checksum")
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
	_, err := a.Service.DB.Exec(r.Context(), `INSERT INTO images(id,name,file_name,source_type,source_location,checksum,sync_status,os_family,version,enabled) VALUES($1,$2,$3,$4,$5,nullif($6,''),$7,$8,$9,$10)`, in.ID, in.Name, in.FileName, in.SourceType, in.SourceLocation, in.Checksum, syncStatus, in.OSFamily, in.Version, enabled)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": in.ID})
}
func (a *API) updateImage(w http.ResponseWriter, r *http.Request) {
	var in imageInput
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Enabled == nil {
		writeError(w, 422, "enabled is required")
		return
	}
	tag, err := a.Service.DB.Exec(r.Context(), `UPDATE images SET enabled=$1 WHERE id=$2 AND sync_status='READY'`, *in.Enabled, r.PathValue("id"))
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

func (a *API) createApplication(w http.ResponseWriter, r *http.Request) {
	var in platform.CreateApplicationInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	actor := r.Header.Get("X-User")
	if actor == "" {
		actor = "developer"
	}
	result, err := a.Service.CreateApplication(r.Context(), actor, in)
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
	actor := r.Header.Get("X-User")
	if actor == "" {
		actor = "developer"
	}
	result, err := a.Service.PerformInstanceAction(r.Context(), actor, r.PathValue("id"), in.Action)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 202, result)
}

func (a *API) renewInstance(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hours int `json:"hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	actor := r.Header.Get("X-User")
	if actor == "" {
		actor = "developer"
	}
	result, err := a.Service.RenewInstance(r.Context(), actor, r.PathValue("id"), in.Hours)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

func (a *API) registerAgent(w http.ResponseWriter, r *http.Request) {
	if !tokenOK(r, a.BootstrapToken, "X-Bootstrap-Token") {
		writeError(w, 401, "invalid bootstrap token")
		return
	}
	var in platform.HostRegistration
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	result, err := a.Service.RegisterHost(r.Context(), in)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	result["runtime_token"] = a.AgentToken
	writeJSON(w, 200, result)
}

func (a *API) agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !tokenOK(r, a.AgentToken, "Authorization") {
		writeError(w, 401, "unauthorized")
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
	if !tokenOK(r, a.AgentToken, "Authorization") {
		writeError(w, 401, "unauthorized")
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
	if !tokenOK(r, a.AgentToken, "Authorization") {
		writeError(w, 401, "unauthorized")
		return
	}
	var result platform.TaskResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	if err := a.Service.CompleteTask(r.Context(), r.PathValue("id"), r.PathValue("taskID"), result); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"accepted": true})
}

func tokenOK(r *http.Request, want, header string) bool {
	got := r.Header.Get(header)
	got = strings.TrimPrefix(got, "Bearer ")
	return want != "" && got == want
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
