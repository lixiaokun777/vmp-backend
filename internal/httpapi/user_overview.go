package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func (a *API) myOverview(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	var overview json.RawMessage
	err := a.Service.DB.QueryRow(r.Context(), `SELECT jsonb_build_object(
		'active_instances',count(*) FILTER(WHERE i.lifecycle_status IN ('PROVISIONING','RUNNING','STOPPED','STARTING','STOPPING','REBOOTING','ERROR')),
		'quota_instances',count(*) FILTER(WHERE i.lifecycle_status<>'RELEASED'),
		'used_cpu',coalesce(sum(i.allocated_cpu) FILTER(WHERE i.lifecycle_status<>'RELEASED'),0),
		'used_memory_mb',coalesce(sum(i.allocated_memory_mb) FILTER(WHERE i.lifecycle_status<>'RELEASED'),0),
		'used_disk_gb',coalesce(sum(i.allocated_disk_gb) FILTER(WHERE i.lifecycle_status<>'RELEASED'),0),
		'nearest_expiry',min(i.expires_at) FILTER(WHERE i.lifecycle_status IN ('PROVISIONING','RUNNING','STOPPED','STARTING','STOPPING','REBOOTING','ERROR') AND i.expires_at>now()),
		'expiring_24h',count(*) FILTER(WHERE i.lifecycle_status IN ('PROVISIONING','RUNNING','STOPPED','STARTING','STOPPING','REBOOTING','ERROR') AND i.expires_at>now() AND i.expires_at<now()+interval '24 hours'),
		'limits',jsonb_build_object('instances',p.max_instances,'cpu',p.max_cpu,'memory_mb',p.max_memory_mb,'disk_gb',p.max_disk_gb))
	FROM platform_policy p LEFT JOIN applications ap ON lower(ap.applicant)=lower($1) LEFT JOIN instances i ON i.application_id=ap.id WHERE p.singleton GROUP BY p.max_instances,p.max_cpu,p.max_memory_mb,p.max_disk_gb`, user.Username).Scan(&overview)
	if err != nil {
		writeError(w, 500, "读取个人资源概览失败")
		return
	}
	writeJSON(w, 200, overview)
}

func (a *API) instanceMetrics(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours == 0 {
		hours = 24
	}
	if hours < 1 || hours > 168 {
		writeError(w, 422, "指标时间范围必须为 1 至 168 小时")
		return
	}
	var allowed bool
	if err := a.Service.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM instances i JOIN applications ap ON ap.id=i.application_id WHERE i.id=$1::uuid AND ($3 OR lower(ap.applicant)=lower($2)))`, r.PathValue("id"), user.Username, user.Role == "ADMIN").Scan(&allowed); err != nil || !allowed {
		writeError(w, 404, "实例不存在")
		return
	}
	items, err := queryRawList(r, a.Service.DB, `SELECT jsonb_build_object('collected_at',collected_at,'cpu_usage_percent',cpu_usage_percent,'memory_usage_mb',memory_usage_mb,'memory_metric_source',memory_metric_source) FROM instance_metrics WHERE instance_id=$1::uuid AND collected_at>=now()-make_interval(hours=>$2) ORDER BY collected_at`, r.PathValue("id"), hours)
	if err != nil {
		writeError(w, 500, "读取实例监控指标失败")
		return
	}
	writeJSON(w, 200, map[string]any{"hours": hours, "items": items})
}
