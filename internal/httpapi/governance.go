package httpapi

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"vmp-backend/internal/platform"
)

func (a *API) registerGovernanceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/console/{mode}", a.consoleProxy)
	mux.HandleFunc("GET /api/v1/platform-policy", a.platformPolicy)
	mux.HandleFunc("PUT /api/v1/platform-policy", a.updatePlatformPolicy)
	mux.HandleFunc("GET /api/v1/instances/{id}/auto-renew", a.autoRenew)
	mux.HandleFunc("PUT /api/v1/instances/{id}/auto-renew", a.updateAutoRenew)
	mux.HandleFunc("GET /api/v1/approval-delegation", a.approvalDelegation)
	mux.HandleFunc("PUT /api/v1/approval-delegation", a.updateApprovalDelegation)
	mux.HandleFunc("POST /api/v1/approvals/{id}/transfer", a.transferApproval)
	mux.HandleFunc("GET /api/v1/history/archives", a.historyArchives)
	mux.HandleFunc("POST /api/v1/history/archives", a.createHistoryArchive)
	mux.HandleFunc("GET /api/v1/history/archives/{id}/download", a.downloadHistoryArchive)
	mux.HandleFunc("POST /api/v1/history/archives/{id}/purge", a.purgeHistoryArchive)
	mux.HandleFunc("DELETE /api/v1/history/archives/{id}", a.deleteHistoryArchive)
}

func (a *API) platformPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := a.Service.GetPolicy(r.Context())
	if err != nil {
		writeError(w, 500, "读取平台策略失败")
		return
	}
	writeJSON(w, 200, p)
}
func (a *API) updatePlatformPolicy(w http.ResponseWriter, r *http.Request) {
	var p platform.GovernancePolicy
	if json.NewDecoder(r.Body).Decode(&p) != nil {
		writeError(w, 400, "平台策略格式无效")
		return
	}
	u, _ := userFromRequest(r)
	if err := a.Service.SavePolicy(r.Context(), u.Username, p); err != nil {
		writeError(w, 422, err.Error())
		return
	}
	a.recordAudit(r.Context(), r, u.Username, "policy.update", "configuration", "platform-policy", "SUCCESS", p)
	writeJSON(w, 200, p)
}

func (a *API) autoRenew(w http.ResponseWriter, r *http.Request) {
	u, _ := userFromRequest(r)
	var allowed bool
	if err := a.Service.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM instances i JOIN applications ap ON ap.id=i.application_id WHERE i.id=$1::uuid AND (ap.applicant=$2 OR $3))`, r.PathValue("id"), u.Username, u.Role == "ADMIN").Scan(&allowed); err != nil || !allowed {
		writeError(w, 404, "实例不存在")
		return
	}
	var raw json.RawMessage
	err := a.Service.DB.QueryRow(r.Context(), `SELECT jsonb_build_object('enabled',enabled,'hours',hours,'max_renewals',max_renewals,'renewed_count',renewed_count,'last_error',last_error) FROM instance_auto_renew WHERE instance_id=$1::uuid`, r.PathValue("id")).Scan(&raw)
	p, pErr := a.Service.GetPolicy(r.Context())
	if pErr != nil {
		writeError(w, 500, "读取自动续期上限失败")
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, 200, map[string]any{"enabled": false, "hours": p.AutoRenewHours, "max_renewals": p.AutoRenewMaxCount, "renewed_count": 0, "last_error": "", "platform_enabled": p.AutoRenewEnabled, "platform_max_count": p.AutoRenewMaxCount, "platform_max_hours": p.AutoRenewHours})
		return
	}
	if err != nil {
		writeError(w, 500, "读取自动续期配置失败")
		return
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		writeError(w, 500, "自动续期配置无效")
		return
	}
	out["platform_enabled"], out["platform_max_count"], out["platform_max_hours"] = p.AutoRenewEnabled, p.AutoRenewMaxCount, p.AutoRenewHours
	writeJSON(w, 200, out)
}
func (a *API) updateAutoRenew(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled     bool `json:"enabled"`
		Hours       int  `json:"hours"`
		MaxRenewals int  `json:"max_renewals"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeError(w, 400, "自动续期配置格式无效")
		return
	}
	u, _ := userFromRequest(r)
	if err := a.Service.SetAutoRenew(r.Context(), u.Username, u.Role == "ADMIN", r.PathValue("id"), in.Enabled, in.Hours, in.MaxRenewals); err != nil {
		writeError(w, 422, err.Error())
		return
	}
	a.autoRenew(w, r)
}

func (a *API) approvalDelegation(w http.ResponseWriter, r *http.Request) {
	u, _ := userFromRequest(r)
	var raw json.RawMessage
	err := a.Service.DB.QueryRow(r.Context(), `SELECT jsonb_build_object('delegate_username',delegate_username,'starts_at',starts_at,'ends_at',ends_at) FROM approval_delegations WHERE owner_username=$1`, u.Username).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		raw = json.RawMessage(`null`)
	} else if err != nil {
		writeError(w, 500, "读取代理配置失败")
		return
	}
	admins, err := queryRawList(r, a.Service.DB, `SELECT jsonb_build_object('username',username,'display_name',display_name) FROM users WHERE role='ADMIN' AND enabled AND (source<>'LDAP' OR ldap_directory_present) ORDER BY username`)
	if err != nil {
		writeError(w, 500, "读取管理员列表失败")
		return
	}
	writeJSON(w, 200, map[string]any{"delegation": raw, "administrators": admins})
}
func (a *API) updateApprovalDelegation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Delegate string    `json:"delegate_username"`
		Start    time.Time `json:"starts_at"`
		End      time.Time `json:"ends_at"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeError(w, 400, "代理配置格式无效")
		return
	}
	u, _ := userFromRequest(r)
	in.Delegate = strings.TrimSpace(in.Delegate)
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, "保存代理配置失败")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(8673230)`); err != nil {
		writeError(w, 500, "锁定代理配置失败")
		return
	}
	if in.Delegate == "" {
		_, err = tx.Exec(r.Context(), `DELETE FROM approval_delegations WHERE owner_username=$1`, u.Username)
	} else {
		if in.Delegate == u.Username || in.Start.IsZero() || !in.End.After(in.Start) || !in.End.After(time.Now()) || in.End.Sub(in.Start) > 90*24*time.Hour {
			writeError(w, 422, "请选择其他管理员，并设置不超过 90 天的有效代理期")
			return
		}
		var valid bool
		err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1 AND role='ADMIN' AND enabled AND (source<>'LDAP' OR ldap_directory_present)) AND NOT EXISTS(SELECT 1 FROM approval_delegations WHERE (owner_username=$1 OR delegate_username=$2) AND starts_at<$3 AND ends_at>$4)`, in.Delegate, u.Username, in.End, in.Start).Scan(&valid)
		if err != nil || !valid {
			writeError(w, 422, "代理人不可用或存在重叠的链式代理，请先解除该代理")
			return
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO approval_delegations(owner_username,delegate_username,starts_at,ends_at) VALUES($1,$2,$3,$4) ON CONFLICT(owner_username) DO UPDATE SET delegate_username=excluded.delegate_username,starts_at=excluded.starts_at,ends_at=excluded.ends_at`, u.Username, in.Delegate, in.Start, in.End)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		writeError(w, 500, "保存代理配置失败")
		return
	}
	if err = a.Service.RefreshDelegations(r.Context()); err != nil {
		writeError(w, 500, "配置已保存但待审批路由刷新失败，请重试")
		return
	}
	a.recordAudit(r.Context(), r, u.Username, "approval.delegation.configure", "configuration", u.Username, "SUCCESS", in)
	a.approvalDelegation(w, r)
}
func (a *API) transferApproval(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reviewer string `json:"reviewer_username"`
		Reason   string `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || strings.TrimSpace(in.Reason) == "" || len(in.Reason) > 1000 {
		writeError(w, 422, "请选择接收管理员并填写简短转交原因")
		return
	}
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, "转交失败")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(8673230)`); err != nil {
		writeError(w, 500, "锁定审批路由失败")
		return
	}
	var valid bool
	if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1 AND role='ADMIN' AND enabled AND (source<>'LDAP' OR ldap_directory_present))`, in.Reviewer).Scan(&valid); err != nil || !valid {
		writeError(w, 422, "接收管理员不可用")
		return
	}
	tag, err := tx.Exec(r.Context(), `UPDATE approval_requests SET assigned_reviewer=$2,delegated_from=NULL,updated_at=now() WHERE id=$1::uuid AND status='PENDING' AND expires_at>now()`, r.PathValue("id"), in.Reviewer)
	if err != nil {
		writeError(w, 422, "审批单编号无效")
		return
	}
	if tag.RowsAffected() != 1 {
		writeError(w, 409, "审批单已处理或超时，不能转交")
		return
	}
	u, _ := userFromRequest(r)
	_, err = tx.Exec(r.Context(), `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'approval.transfer','approval',$2,jsonb_build_object('reviewer',$3::text,'reason',$4::text))`, u.Username, r.PathValue("id"), in.Reviewer, in.Reason)
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		writeError(w, 500, "转交失败")
		return
	}
	writeJSON(w, 200, map[string]any{"assigned_reviewer": in.Reviewer})
}

func (a *API) historyArchives(w http.ResponseWriter, r *http.Request) {
	a.queryList(w, r, `SELECT jsonb_build_object('id',id,'category',category,'checksum',checksum,'row_count',row_count,'created_at',created_at,'created_by',created_by,'downloaded_at',downloaded_at,'purged_at',purged_at,'size_bytes',octet_length(data)) FROM history_archives ORDER BY created_at DESC LIMIT 100`)
}

type archiveSource struct {
	table, condition string
	days             int
}

func sourceForArchive(category string, p platform.GovernancePolicy) (archiveSource, error) {
	switch category {
	case "audit":
		return archiveSource{"audit_logs", "true", p.AuditRetentionDays}, nil
	case "notifications":
		return archiveSource{"notification_events", "status IN ('SENT','FAILED','CANCELLED') AND NOT EXISTS(SELECT 1 FROM platform_notification_outbox po WHERE po.id=t.instance_id AND po.status='PENDING')", p.NotificationRetentionDays}, nil
	case "approvals":
		return archiveSource{"approval_requests", "status IN ('APPROVED','REJECTED','WITHDRAWN','EXPIRED','FAILED','APPROVED_FAILED')", p.ApprovalRetentionDays}, nil
	}
	return archiveSource{}, errors.New("归档类型无效")
}
func (a *API) createHistoryArchive(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Category string `json:"category"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeError(w, 400, "归档参数无效")
		return
	}
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, "创建归档失败")
		return
	}
	defer tx.Rollback(r.Context())
	p, err := a.Service.GetPolicyTx(r.Context(), tx)
	if err != nil {
		writeError(w, 500, "读取历史策略失败")
		return
	}
	src, err := sourceForArchive(in.Category, p)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	if src.days == 0 {
		writeError(w, 422, "该历史类型当前永久保留；请先配置保留期限")
		return
	}
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(8673231)`); err != nil {
		writeError(w, 500, "锁定归档失败")
		return
	}
	cutoff := time.Now().Add(-time.Duration(src.days) * 24 * time.Hour)
	jsonExpression := "to_jsonb(t)"
	if in.Category == "notifications" {
		jsonExpression += `||jsonb_build_object('platform_event',(SELECT to_jsonb(po) FROM platform_notification_outbox po WHERE po.id=t.instance_id))`
	}
	sql := fmt.Sprintf(`SELECT t.id::text,%s,encode(digest(to_jsonb(t)::text,'sha256'),'hex') FROM %s t WHERE created_at<$1 AND %s AND NOT EXISTS(SELECT 1 FROM history_archives ar WHERE ar.category=$2 AND ar.purged_at IS NULL AND t.id::text=ANY(ar.source_ids)) ORDER BY created_at,id LIMIT 5000 FOR SHARE`, jsonExpression, src.table, src.condition)
	rows, err := tx.Query(r.Context(), sql, cutoff, in.Category)
	if err != nil {
		writeError(w, 500, "读取待归档历史失败")
		return
	}
	var data bytes.Buffer
	z := gzip.NewWriter(&data)
	ids := []string{}
	hashes := []string{}
	size := 0
	for rows.Next() {
		var id string
		var rowHash string
		var raw []byte
		if err = rows.Scan(&id, &raw, &rowHash); err != nil {
			break
		}
		size += len(raw) + 1
		if size > 32<<20 {
			break
		}
		ids = append(ids, id)
		hashes = append(hashes, rowHash)
		if _, err = z.Write(append(raw, '\n')); err != nil {
			break
		}
	}
	rowErr := rows.Err()
	rows.Close()
	closeErr := z.Close()
	if err != nil || rowErr != nil || closeErr != nil {
		writeError(w, 500, "生成历史归档失败")
		return
	}
	if len(ids) == 0 {
		writeError(w, 422, "没有达到期限的可归档历史")
		return
	}
	sum := sha256.Sum256(data.Bytes())
	checksum := hex.EncodeToString(sum[:])
	u, _ := userFromRequest(r)
	var id string
	var created time.Time
	err = tx.QueryRow(r.Context(), `INSERT INTO history_archives(category,checksum,row_count,source_ids,data,cutoff,created_by,source_hashes) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id::text,created_at`, in.Category, checksum, len(ids), ids, data.Bytes(), cutoff, u.Username, hashes).Scan(&id, &created)
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		writeError(w, 500, "保存归档失败")
		return
	}
	a.recordAudit(r.Context(), r, u.Username, "history.archive", "history", id, "SUCCESS", map[string]any{"category": in.Category, "row_count": len(ids), "checksum": checksum})
	writeJSON(w, 201, map[string]any{"id": id, "category": in.Category, "row_count": len(ids), "checksum": checksum, "created_at": created})
}
func (a *API) downloadHistoryArchive(w http.ResponseWriter, r *http.Request) {
	var data []byte
	var checksum, category string
	if err := a.Service.DB.QueryRow(r.Context(), `UPDATE history_archives SET downloaded_at=now() WHERE id=$1::uuid RETURNING data,checksum,category`, r.PathValue("id")).Scan(&data, &checksum, &category); err != nil {
		writeError(w, 404, "归档不存在")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vmp-%s-%s.ndjson.gz"`, category, r.PathValue("id")))
	w.Header().Set("X-Archive-SHA256", checksum)
	w.Write(data)
}
func (a *API) purgeHistoryArchive(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Checksum string `json:"checksum"`
		Confirm  string `json:"confirm"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Confirm != "已下载并校验归档" {
		writeError(w, 422, "请先下载、校验并确认归档")
		return
	}
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, "清理失败")
		return
	}
	defer tx.Rollback(r.Context())
	var category, checksum string
	var ids []string
	var hashes []string
	var downloaded, purged *time.Time
	var cutoff time.Time
	if err = tx.QueryRow(r.Context(), `SELECT category,checksum,source_ids,downloaded_at,purged_at,cutoff,source_hashes FROM history_archives WHERE id=$1::uuid FOR UPDATE`, r.PathValue("id")).Scan(&category, &checksum, &ids, &downloaded, &purged, &cutoff, &hashes); err != nil {
		writeError(w, 404, "归档不存在")
		return
	}
	if checksum != in.Checksum || downloaded == nil || purged != nil {
		writeError(w, 409, "归档未下载、校验值不符或已清理")
		return
	}
	p, err := a.Service.GetPolicyTx(r.Context(), tx)
	if err != nil {
		writeError(w, 500, "读取保留策略失败")
		return
	}
	src, err := sourceForArchive(category, p)
	if err != nil || src.days == 0 {
		writeError(w, 422, "当前策略禁止清理该类历史")
		return
	}
	currentCutoff := time.Now().Add(-time.Duration(src.days) * 24 * time.Hour)
	if cutoff.After(currentCutoff) {
		cutoff = currentCutoff
	}
	// 同时检查精确 ID、归档时行摘要、终态和最新期限；归档后改变的记录不会被删除。
	sql := fmt.Sprintf(`DELETE FROM %s t USING unnest($1::text[],$3::text[]) archived(id,hash) WHERE t.id::text=archived.id AND encode(digest(to_jsonb(t)::text,'sha256'),'hex')=archived.hash AND created_at<$2 AND %s`, src.table, src.condition)
	// 返回被删通知关联的队列 ID；仅清理本次已归档的终态事件，不误删待发送队列。
	if category == "notifications" {
		sql += ` RETURNING t.instance_id::text`
		rows, deleteErr := tx.Query(r.Context(), sql, ids, cutoff, hashes)
		if deleteErr != nil {
			writeError(w, 500, "清理失败，已回滚")
			return
		}
		var eventIDs []string
		var deletedCount int64
		for rows.Next() {
			var id *string
			if deleteErr = rows.Scan(&id); deleteErr != nil {
				break
			}
			deletedCount++
			if id != nil {
				eventIDs = append(eventIDs, *id)
			}
		}
		rowsErr := rows.Err()
		rows.Close()
		if deleteErr != nil || rowsErr != nil {
			writeError(w, 500, "清理失败，已回滚")
			return
		}
		if _, deleteErr = tx.Exec(r.Context(), `DELETE FROM platform_notification_outbox WHERE id=ANY($1::uuid[]) AND status IN ('SENT','FAILED','CANCELLED') AND created_at<$2`, eventIDs, cutoff); deleteErr != nil {
			writeError(w, 500, "清理失败，已回滚")
			return
		}
		if _, err = tx.Exec(r.Context(), `UPDATE history_archives SET purged_at=now() WHERE id=$1::uuid`, r.PathValue("id")); err != nil {
			writeError(w, 500, "清理失败，已回滚")
			return
		}
		u, _ := userFromRequest(r)
		if _, err = tx.Exec(r.Context(), `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'history.purge','history',$2,jsonb_build_object('category',$3::text,'deleted_count',$4::integer,'checksum',$5::text))`, u.Username, r.PathValue("id"), category, int(deletedCount), checksum); err != nil {
			writeError(w, 500, "清理失败，已回滚")
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			writeError(w, 500, "清理失败，已回滚")
			return
		}
		writeJSON(w, 200, map[string]any{"deleted_count": deletedCount, "archive_retained": true})
		return
	}
	tag, err := tx.Exec(r.Context(), sql, ids, cutoff, hashes)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE history_archives SET purged_at=now() WHERE id=$1::uuid`, r.PathValue("id"))
	}
	u, _ := userFromRequest(r)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'history.purge','history',$2,jsonb_build_object('category',$3::text,'deleted_count',$4::integer,'checksum',$5::text))`, u.Username, r.PathValue("id"), category, int(tag.RowsAffected()), checksum)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		writeError(w, 500, "清理失败，已回滚")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted_count": tag.RowsAffected(), "archive_retained": true})
}
func (a *API) deleteHistoryArchive(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Checksum string `json:"checksum"`
		Confirm  string `json:"confirm"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Confirm != "已备份归档" {
		writeError(w, 422, "请确认已备份该归档")
		return
	}
	tag, err := a.Service.DB.Exec(r.Context(), `DELETE FROM history_archives WHERE id=$1::uuid AND checksum=$2 AND downloaded_at IS NOT NULL AND purged_at IS NOT NULL`, r.PathValue("id"), in.Checksum)
	if err != nil || tag.RowsAffected() != 1 {
		writeError(w, 409, "归档未清理源记录、未下载或校验值不符")
		return
	}
	u, _ := userFromRequest(r)
	a.recordAudit(r.Context(), r, u.Username, "history.archive.delete", "history", r.PathValue("id"), "SUCCESS", map[string]any{"checksum": in.Checksum})
	w.WriteHeader(204)
}
