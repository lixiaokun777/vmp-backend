package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// auditResponseWriter 记录接口最终状态码，便于对管理类操作统一留痕。
type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func requestSourceIP(r *http.Request) string {
	value := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		value = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}
	return value
}

func (a *API) recordAudit(ctx context.Context, r *http.Request, actor, action, resourceType, resourceID, outcome string, detail any) {
	if actor == "" {
		actor = "anonymous"
	}
	if resourceID == "" {
		resourceID = "-"
	}
	if outcome == "" {
		outcome = "SUCCESS"
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		payload = []byte(`{}`)
	}
	requestID := r.Header.Get("X-Request-ID")
	_, _ = a.Service.DB.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail,outcome,source_ip,user_agent,request_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, actor, action, resourceType, resourceID, payload, outcome, requestSourceIP(r), r.UserAgent(), requestID)
}

// auditMutation 只补齐管理类变更。申请和实例生命周期由业务事务自身记录，避免重复。
func (a *API) auditMutation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action, resourceType, resourceID, ok := auditMutationTarget(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		wrapped := &auditResponseWriter{ResponseWriter: w}
		next.ServeHTTP(wrapped, r)
		status := wrapped.status
		if status == 0 {
			status = http.StatusOK
		}
		user, _ := userFromRequest(r)
		outcome := "SUCCESS"
		if status >= 400 {
			outcome = "FAILED"
		}
		a.recordAudit(r.Context(), r, user.Username, action, resourceType, resourceID, outcome, map[string]any{"method": r.Method, "path": r.URL.Path, "status_code": status})
	})
}

func auditMutationTarget(r *http.Request) (string, string, string, bool) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return "", "", "", false
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return "", "", "", false
	}
	resourceID := "-"
	if len(parts) > 1 && parts[1] != "" {
		resourceID = parts[1]
	}
	switch parts[0] {
	case "users":
		action := "user.create"
		if r.Method == http.MethodPatch {
			action = "user.update"
		} else if r.Method == http.MethodDelete {
			action = "user.delete"
		} else if len(parts) > 2 && parts[2] == "password" {
			action = "user.reset_password"
		}
		return action, "user", resourceID, true
	case "ldap":
		action := "ldap." + resourceID
		return action, "configuration", "ldap", true
	case "notifications":
		return "notifications." + resourceID, "configuration", "notifications", true
	case "hosts", "flavors", "images", "networks":
		actionName := map[string]string{http.MethodPost: "create", http.MethodPatch: "update", http.MethodDelete: "delete"}[r.Method]
		if len(parts) > 2 {
			actionName = parts[2]
		}
		return parts[0] + "." + actionName, strings.TrimSuffix(parts[0], "s"), resourceID, true
	default:
		return "", "", "", false
	}
}

func (a *API) auditLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	pageSize, _ := strconv.Atoi(query.Get("page_size"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}
	conditions := []string{"true"}
	args := make([]any, 0)
	add := func(sql string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(sql, len(args)))
	}
	if keyword := strings.TrimSpace(query.Get("keyword")); keyword != "" {
		args = append(args, keyword)
		position := len(args)
		conditions = append(conditions, fmt.Sprintf("(actor ILIKE '%%' || $%d || '%%' OR action ILIKE '%%' || $%d || '%%' OR resource_id ILIKE '%%' || $%d || '%%')", position, position, position))
	}
	if action := strings.TrimSpace(query.Get("action")); action != "" {
		add("action=$%d", action)
	}
	if resourceType := strings.TrimSpace(query.Get("resource_type")); resourceType != "" {
		add("resource_type=$%d", resourceType)
	}
	if outcome := strings.TrimSpace(query.Get("outcome")); outcome != "" {
		add("outcome=$%d", outcome)
	}
	// 默认只展示人工操作；系统事件保留在同一存储中，但需显式切换查看。
	scope := strings.ToUpper(strings.TrimSpace(query.Get("scope")))
	if scope == "" {
		scope = "HUMAN"
	}
	switch scope {
	case "HUMAN":
		conditions = append(conditions, "lower(actor) <> ALL(ARRAY['system','scheduler','agent'])")
	case "SYSTEM":
		conditions = append(conditions, "lower(actor) = ANY(ARRAY['system','scheduler','agent'])")
	case "ALL":
	default:
		writeError(w, 422, "scope 参数无效")
		return
	}
	for _, item := range []struct{ key, operator string }{{"from", ">="}, {"to", "<="}} {
		if value := strings.TrimSpace(query.Get(item.key)); value != "" {
			parsed, err := time.Parse(time.RFC3339, value)
			if err != nil {
				writeError(w, 422, item.key+"时间格式无效")
				return
			}
			add("created_at"+item.operator+"$%d", parsed)
		}
	}
	where := " WHERE " + strings.Join(conditions, " AND ")
	var total int
	if err := a.Service.DB.QueryRow(r.Context(), "SELECT count(*) FROM audit_logs"+where, args...).Scan(&total); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := queryRawList(r, a.Service.DB, `SELECT jsonb_build_object('id',id,'actor',actor,'action',action,'resource_type',resource_type,'resource_id',resource_id,'outcome',outcome,'source_ip',source_ip,'user_agent',user_agent,'request_id',request_id,'detail',detail,'created_at',created_at) FROM audit_logs`+where+fmt.Sprintf(" ORDER BY created_at DESC,id DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2), listArgs...)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	// 筛选项由真实审计数据生成，新增动作后前端无需同步硬编码。
	actionRows, err := a.Service.DB.Query(r.Context(), `SELECT DISTINCT action FROM audit_logs ORDER BY action`)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	defer actionRows.Close()
	actions := make([]string, 0)
	for actionRows.Next() {
		var action string
		if actionRows.Scan(&action) == nil {
			actions = append(actions, action)
		}
	}
	resourceRows, err := a.Service.DB.Query(r.Context(), `SELECT DISTINCT resource_type FROM audit_logs ORDER BY resource_type`)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	defer resourceRows.Close()
	resourceTypes := make([]string, 0)
	for resourceRows.Next() {
		var resourceType string
		if resourceRows.Scan(&resourceType) == nil {
			resourceTypes = append(resourceTypes, resourceType)
		}
	}
	writeJSON(w, 200, map[string]any{"items": rows, "page": page, "page_size": pageSize, "total": total, "actions": actions, "resource_types": resourceTypes, "scope": scope})
}
