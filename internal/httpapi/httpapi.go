package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
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
	mux.HandleFunc("GET /api/v1/flavors", a.flavors)
	mux.HandleFunc("POST /api/v1/flavors", a.createFlavor)
	mux.HandleFunc("PATCH /api/v1/flavors/{id}", a.updateFlavor)
	mux.HandleFunc("GET /api/v1/images", a.images)
	mux.HandleFunc("POST /api/v1/images", a.createImage)
	mux.HandleFunc("PATCH /api/v1/images/{id}", a.updateImage)
	mux.HandleFunc("GET /api/v1/networks", a.networks)
	mux.HandleFunc("GET /api/v1/ip-addresses", a.ipAddresses)
	mux.HandleFunc("GET /api/v1/applications", a.applications)
	mux.HandleFunc("POST /api/v1/applications", a.createApplication)
	mux.HandleFunc("GET /api/v1/instances", a.instances)
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
	a.queryList(w, r, `SELECT jsonb_build_object('id',h.id,'name',h.name,'provider_type',h.provider_type,'agent_mode',h.agent_mode,'status',h.status,'management_ip',h.management_ip,'allocatable_cpu',h.allocatable_cpu,'allocatable_memory_mb',h.allocatable_memory_mb,'allocatable_disk_gb',h.allocatable_disk_gb,'reserved_cpu',h.reserved_cpu,'reserved_memory_mb',h.reserved_memory_mb,'reserved_disk_gb',h.reserved_disk_gb,'last_heartbeat_at',h.last_heartbeat_at,'last_inventory_at',h.last_inventory_at,'facts',h.facts,'discovered_instances',(SELECT count(*) FROM discovered_instances d WHERE d.host_id=h.id),'external_instances',(SELECT count(*) FROM discovered_instances d WHERE d.host_id=h.id AND d.ownership='EXTERNAL')) FROM hosts h ORDER BY h.name`)
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
	a.queryList(w, r, `SELECT jsonb_build_object('id',id,'name',name,'file_name',file_name,'os_family',os_family,'version',version,'enabled',enabled) FROM images`+filter+` ORDER BY name`)
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
	a.queryListArgs(w, r, `SELECT jsonb_build_object('id',i.id,'name',i.name,'owner',a.applicant,'host',h.name,'flavor',f.name,'image',im.name,'lifecycle_status',i.lifecycle_status,'provider_status',i.provider_status,'ip_address',i.ip_address,'username',i.username,'expires_at',i.expires_at,'created_at',i.created_at) FROM instances i JOIN applications a ON a.id=i.application_id JOIN flavors f ON f.id=a.flavor_id JOIN images im ON im.id=a.image_id LEFT JOIN hosts h ON h.id=i.host_id`+where+` ORDER BY i.created_at DESC`, args...)
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
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Enabled == nil {
		writeError(w, 422, "enabled is required")
		return
	}
	_, err := a.Service.DB.Exec(r.Context(), `UPDATE flavors SET enabled=$1 WHERE id=$2`, *in.Enabled, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": *in.Enabled})
}

type imageInput struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	OSFamily string `json:"os_family"`
	Version  string `json:"version"`
	Enabled  *bool  `json:"enabled"`
}

var imageFileNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func (a *API) createImage(w http.ResponseWriter, r *http.Request) {
	var in imageInput
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.ID == "" || in.Name == "" || !imageFileNamePattern.MatchString(in.FileName) || in.OSFamily == "" || in.Version == "" {
		writeError(w, 422, "invalid image")
		return
	}
	_, err := a.Service.DB.Exec(r.Context(), `INSERT INTO images(id,name,file_name,os_family,version) VALUES($1,$2,$3,$4,$5)`, in.ID, in.Name, in.FileName, in.OSFamily, in.Version)
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
	_, err := a.Service.DB.Exec(r.Context(), `UPDATE images SET enabled=$1 WHERE id=$2`, *in.Enabled, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
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
