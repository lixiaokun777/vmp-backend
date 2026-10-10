package httpapi

import (
	"github.com/google/uuid"
	"net/http"
	"strings"
)

func (a *API) usersPage(w http.ResponseWriter, r *http.Request) {
	f := listConditions{}
	for _, entry := range []struct {
		key, column string
		allowed     []string
	}{{"role", "u.role", []string{"ADMIN", "USER"}}, {"source", "u.source", []string{"LOCAL", "LDAP"}}} {
		value, ok := enumFilter(w, r, entry.key, entry.allowed...)
		if !ok {
			return
		}
		if value != "" {
			f.add(entry.column+"=$%d", value)
		}
	}
	status, ok := enumFilter(w, r, "status", "ENABLED", "DISABLED", "DIRECTORY_UNAVAILABLE", "MUST_CHANGE_PASSWORD")
	if !ok {
		return
	}
	switch status {
	case "ENABLED":
		f.parts = append(f.parts, "u.enabled AND (u.source<>'LDAP' OR u.ldap_directory_present)")
	case "DISABLED":
		f.parts = append(f.parts, "NOT u.enabled")
	case "DIRECTORY_UNAVAILABLE":
		f.parts = append(f.parts, "u.enabled AND u.source='LDAP' AND NOT u.ldap_directory_present")
	case "MUST_CHANGE_PASSWORD":
		f.parts = append(f.parts, "u.enabled AND u.must_change_password")
	}
	if keyword := strings.TrimSpace(r.URL.Query().Get("keyword")); keyword != "" {
		f.add("(u.username ILIKE '%%'||$%[1]d||'%%' OR u.display_name ILIKE '%%'||$%[1]d||'%%' OR u.email ILIKE '%%'||$%[1]d||'%%')", keyword)
	}
	a.queryPage(w, r, `jsonb_build_object('id',u.id,'username',u.username,'display_name',u.display_name,'email',u.email,'role',u.role,'source',u.source,'enabled',u.enabled,'ldap_directory_present',u.ldap_directory_present,'must_change_password',u.must_change_password,'last_login_at',u.last_login_at,'created_at',u.created_at)`, "FROM users u", "ORDER BY u.role,u.username,u.id", f)
}
func (a *API) instancesPage(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	f := listConditions{parts: []string{"i.lifecycle_status<>'RELEASED'"}}
	if r.URL.Query().Get("all") != "1" {
		f.parts = append(f.parts, "coalesce(h.agent_mode,'')<>'mock'")
	}
	if user.Role != "ADMIN" || r.URL.Query().Get("scope") == "mine" {
		f.add("a.applicant=$%d", user.Username)
	}
	scopeParts := append([]string{}, f.parts...)
	scopeArgs := append([]any{}, f.args...)
	status, ok := enumFilter(w, r, "status", "PROVISIONING", "RUNNING", "STOPPED", "STOPPING", "STARTING", "REBOOTING", "RETAINED", "DELETING", "ERROR", "RELEASED")
	if !ok {
		return
	}
	if status != "" {
		f.add("i.lifecycle_status=$%d", status)
	}
	if host := r.URL.Query().Get("host_id"); host != "" {
		if _, err := uuid.Parse(host); err != nil {
			writeError(w, 422, "宿主机筛选标识无效")
			return
		}
		f.add("i.host_id=$%d::uuid", host)
	}
	if keyword := strings.TrimSpace(r.URL.Query().Get("keyword")); keyword != "" {
		f.add("(i.name ILIKE '%%'||$%[1]d||'%%' OR a.applicant ILIKE '%%'||$%[1]d||'%%' OR coalesce(host(i.ip_address),'') ILIKE '%%'||$%[1]d||'%%')", keyword)
	}
	item := `jsonb_build_object('id',i.id,'name',i.name,'owner',a.applicant,'host',h.name,'host_id',i.host_id,'flavor',i.flavor_name_snapshot,'flavor_id',a.flavor_id,'resource_snapshot',jsonb_build_object('cpu',i.allocated_cpu,'memory_mb',i.allocated_memory_mb,'disk_gb',i.allocated_disk_gb),'image',im.name,'lifecycle_status',i.lifecycle_status,'provider_status',i.provider_status,'delivery_status',i.delivery_status,'delivery_message',i.delivery_message,'observed_domain_status',i.observed_domain_status,'last_domain_seen_at',i.last_domain_seen_at,'network_id',i.network_id,'ip_address',i.ip_address,'username',i.username,'expires_at',i.expires_at,'retention_until',i.retention_until,'restore_count',i.restore_count,'ip_recovery_pending',i.ip_recovery_pending,'ip_recovery_message',i.ip_recovery_message,'ip_recovery_task_id',i.ip_recovery_task_id,'created_at',i.created_at)`
	scopeParts = append(scopeParts, "i.lifecycle_status IN ('RUNNING','STOPPED','STARTING','REBOOTING') AND i.expires_at>now() AND i.expires_at<now()+interval '24 hours'")
	a.queryPage(w, r, item, "FROM instances i JOIN applications a ON a.id=i.application_id JOIN images im ON im.id=a.image_id LEFT JOIN hosts h ON h.id=i.host_id", "ORDER BY i.created_at DESC,i.id DESC", f, pageMetadata{key: "expiring_total", query: "SELECT count(*) FROM instances i JOIN applications a ON a.id=i.application_id LEFT JOIN hosts h ON h.id=i.host_id WHERE " + strings.Join(scopeParts, " AND "), args: scopeArgs})
}
func (a *API) approvalsPage(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	f := listConditions{}
	if user.Role != "ADMIN" || r.URL.Query().Get("scope") == "mine" {
		f.add("ar.applicant=$%d", user.Username)
	}
	status, ok := enumFilter(w, r, "status", "PENDING", "PROCESSING", "APPROVED", "APPROVED_FAILED", "REJECTED", "EXPIRED", "WITHDRAWN", "FAILED")
	if !ok {
		return
	}
	if status != "" {
		f.add("ar.status=$%d", status)
	}
	typeValue, ok := enumFilter(w, r, "type", "CREATE", "RENEW", "RESTORE")
	if !ok {
		return
	}
	if typeValue != "" {
		f.add("ar.request_type=$%d", typeValue)
	}
	if keyword := strings.TrimSpace(r.URL.Query().Get("keyword")); keyword != "" {
		f.add("(ar.request_no ILIKE '%%'||$%[1]d||'%%' OR ar.applicant ILIKE '%%'||$%[1]d||'%%' OR ar.reason ILIKE '%%'||$%[1]d||'%%' OR coalesce(i.name,ar.payload->>'instance_name','') ILIKE '%%'||$%[1]d||'%%')", keyword)
	}
	item := `jsonb_build_object('id',ar.id,'request_no',ar.request_no,'request_type',ar.request_type,'applicant',ar.applicant,'instance_id',ar.instance_id,'instance_name',coalesce(i.name,ar.payload->>'instance_name','-'),'requested_hours',ar.requested_hours,'reason',ar.reason,'status',ar.status,'reviewer',ar.reviewer,'assigned_reviewer',ar.assigned_reviewer,'delegated_from',ar.delegated_from,'review_comment',ar.review_comment,'result',ar.result,'created_at',ar.created_at,'expires_at',ar.expires_at,'reviewed_at',ar.reviewed_at)`
	a.queryPage(w, r, item, "FROM approval_requests ar LEFT JOIN instances i ON i.id=ar.instance_id", "ORDER BY CASE ar.status WHEN 'PENDING' THEN 0 WHEN 'PROCESSING' THEN 1 ELSE 2 END,ar.created_at DESC,ar.id DESC", f)
}
func (a *API) ipAddressesPage(w http.ResponseWriter, r *http.Request) {
	network := r.URL.Query().Get("network_id")
	if _, err := uuid.Parse(network); err != nil {
		writeError(w, 422, "请选择有效网络")
		return
	}
	f := listConditions{}
	f.add("ip.network_id=$%d::uuid", network)
	status, ok := enumFilter(w, r, "status", "FREE", "ALLOCATED", "RESERVED", "QUARANTINED")
	if !ok {
		return
	}
	if status != "" {
		f.add("ip.status=$%d", status)
	}
	if keyword := strings.TrimSpace(r.URL.Query().Get("keyword")); keyword != "" {
		f.add("(host(ip.address) ILIKE '%%'||$%[1]d||'%%' OR coalesce(i.name,'') ILIKE '%%'||$%[1]d||'%%' OR coalesce(ap.applicant,'') ILIKE '%%'||$%[1]d||'%%')", keyword)
	}
	a.queryPage(w, r, `jsonb_build_object('id',ip.id,'address',host(ip.address),'status',ip.status,'instance_id',ip.instance_id,'instance_name',i.name,'owner',ap.applicant,'lifecycle_status',i.lifecycle_status,'allocated_at',ip.allocated_at,'reserved_at',ip.reserved_at,'last_probe_status',ip.last_probe_status,'last_probe_at',ip.last_probe_at,'last_probe_message',ip.last_probe_message,'last_probe_host_id',ip.last_probe_host_id,'last_probe_host',(SELECT h.name FROM hosts h WHERE h.id=ip.last_probe_host_id),'probe_pending',EXISTS(SELECT 1 FROM tasks pt WHERE pt.resource_id=ip.id AND pt.task_type='PROBE_IP_ADDRESS' AND pt.status IN ('PENDING','RUNNING')),'updated_at',ip.updated_at)`, "FROM ip_addresses ip LEFT JOIN instances i ON i.id=ip.instance_id LEFT JOIN applications ap ON ap.id=i.application_id", "ORDER BY ip.address,ip.id", f)
}
