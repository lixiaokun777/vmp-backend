package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"vmp-backend/internal/platform"
)

// 全局引导凭据只允许纳管新的宿主，已纳管名称必须证明已有独立身份。
func (a *API) registerScopedAgent(w http.ResponseWriter, r *http.Request) {
	if !tokenOK(r, a.BootstrapToken, "X-Bootstrap-Token") && agentBearerToken(r) == "" {
		writeError(w, 401, "宿主注册需要有效引导凭据或已有独立运行凭据")
		return
	}
	var input struct {
		platform.HostRegistration
		HostID string `json:"host_id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&input) != nil || !resourceIdentifierPattern.MatchString(input.Name) || input.AllocatableCPU < 0 || input.AllocatableMemoryMB < 1024 || input.AllocatableDiskGB < 0 {
		writeError(w, 422, "宿主机注册信息无效")
		return
	}
	if input.Mode != "kvm" && input.Mode != "kvm-readonly" && input.Mode != "mock" {
		writeError(w, 422, "宿主机模式无效")
		return
	}
	input.ManagementIP = strings.TrimSpace(input.ManagementIP)
	if input.ManagementIP != "" {
		address, err := netip.ParseAddr(input.ManagementIP)
		if err != nil || address.Zone() != "" {
			writeError(w, 422, "宿主机管理地址必须是合法IP，不能包含网段或区域标识")
			return
		}
		input.ManagementIP = address.String()
	}
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 503, "宿主身份服务暂不可用")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "agent-register:"+input.Name); err != nil {
		writeError(w, 503, "宿主身份服务暂不可用")
		return
	}
	var hostID, status string
	err = tx.QueryRow(r.Context(), `SELECT id::text,status FROM hosts WHERE name=$1 FOR UPDATE`, input.Name).Scan(&hostID, &status)
	newHost := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !newHost {
		writeError(w, 503, "宿主身份服务暂不可用")
		return
	}
	runtimeToken := ""
	if newHost {
		if input.HostID != "" || !tokenOK(r, a.BootstrapToken, "X-Bootstrap-Token") {
			writeError(w, 401, "首次纳管需要有效引导令牌；已有宿主请使用独立凭据")
			return
		}
		status = "CORDONED"
		if err = tx.QueryRow(r.Context(), `INSERT INTO hosts(name,provider_type,agent_mode,status,management_ip,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb,quota_cpu,quota_memory_mb,quota_disk_gb,last_heartbeat_at) VALUES($1,'kvm',$2,$3,nullif($4,'')::inet,$5,$6,$7,$5,$6,$7,$5,$6,$7,now()) RETURNING id::text`, input.Name, input.Mode, status, input.ManagementIP, input.AllocatableCPU, input.AllocatableMemoryMB, input.AllocatableDiskGB).Scan(&hostID); err != nil {
			writeError(w, 422, "宿主机地址或资源信息无效")
			return
		}
		runtimeToken, err = generateAgentToken()
		if err != nil {
			writeError(w, 500, "无法生成宿主独立凭据")
			return
		}
		hash := sha256.Sum256([]byte(runtimeToken))
		if _, err = tx.Exec(r.Context(), `INSERT INTO host_credentials(host_id,token_hash) VALUES($1::uuid,$2)`, hostID, hash[:]); err != nil {
			writeError(w, 500, "无法保存宿主独立凭据")
			return
		}
	} else {
		if input.HostID != "" && input.HostID != hostID || !scopedAgentTokenOK(r.Context(), tx, hostID, agentBearerToken(r)) {
			writeError(w, 401, "已有宿主必须使用独立运行凭据；丢失或升级凭据请联系管理员重新签发")
			return
		}
		// 续注册不提供管理地址表示保持原纳管值，不能从来源连接地址推断或清空它。
		if err = tx.QueryRow(r.Context(), `UPDATE hosts SET agent_mode=$2,status=CASE WHEN $2='kvm-readonly' THEN 'CORDONED' WHEN status IN ('CORDONED','MAINTENANCE') THEN status ELSE 'ACTIVE' END,management_ip=coalesce(nullif($3,'')::inet,management_ip),agent_allocatable_cpu=$4,agent_allocatable_memory_mb=$5,agent_allocatable_disk_gb=$6,allocatable_cpu=least($4,coalesce(quota_cpu,$4)),allocatable_memory_mb=least($5,coalesce(quota_memory_mb,$5)),allocatable_disk_gb=least($6,coalesce(quota_disk_gb,$6)),last_heartbeat_at=now(),updated_at=now() WHERE id=$1::uuid RETURNING status`, hostID, input.Mode, input.ManagementIP, input.AllocatableCPU, input.AllocatableMemoryMB, input.AllocatableDiskGB).Scan(&status); err != nil {
			writeError(w, 422, "宿主机地址或资源信息无效")
			return
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, 503, "宿主身份登记失败，请重试")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	response := map[string]any{"id": hostID, "name": input.Name, "status": status}
	if runtimeToken != "" {
		response["runtime_token"] = runtimeToken
	}
	writeJSON(w, 200, response)
}

func generateAgentToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "vmpa_" + base64.RawURLEncoding.EncodeToString(value), nil
}

func agentBearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(value, "Bearer ")
}

type credentialQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func scopedAgentTokenOK(ctx context.Context, db credentialQueryer, hostID, token string) bool {
	if _, err := uuid.Parse(hostID); err != nil || !strings.HasPrefix(token, "vmpa_") || len(token) != 48 {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	var valid bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM host_credentials WHERE host_id=$1::uuid AND token_hash=$2 AND revoked_at IS NULL)`, hostID, hash[:]).Scan(&valid)
	return err == nil && valid
}

func (a *API) authorizeAgent(w http.ResponseWriter, r *http.Request) bool {
	if !scopedAgentTokenOK(r.Context(), a.Service.DB, r.PathValue("id"), agentBearerToken(r)) {
		writeError(w, 401, "宿主独立凭据无效、已吊销或与目标宿主不匹配")
		return false
	}
	return true
}

func (a *API) rotateHostCredential(w http.ResponseWriter, r *http.Request) {
	token, err := generateAgentToken()
	if err != nil {
		writeError(w, 500, "无法生成宿主凭据")
		return
	}
	hash := sha256.Sum256([]byte(token))
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 503, "宿主身份服务暂不可用")
		return
	}
	defer tx.Rollback(r.Context())
	var name, status string
	if err := tx.QueryRow(r.Context(), `UPDATE hosts SET status=CASE WHEN status='MAINTENANCE' THEN status ELSE 'CORDONED' END,updated_at=now() WHERE id=$1::uuid RETURNING name,status`, r.PathValue("id")).Scan(&name, &status); err != nil {
		writeError(w, 404, "宿主机不存在")
		return
	}
	var generation int64
	if err = tx.QueryRow(r.Context(), `INSERT INTO host_credentials(host_id,token_hash) VALUES($1::uuid,$2) ON CONFLICT(host_id) DO UPDATE SET token_hash=excluded.token_hash,generation=host_credentials.generation+1,revoked_at=NULL,updated_at=now() RETURNING generation`, r.PathValue("id"), hash[:]).Scan(&generation); err != nil {
		writeError(w, 500, "无法签发宿主凭据")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, 503, "宿主凭据签发未完成，请重试")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"host_id": r.PathValue("id"), "name": name, "runtime_token": token, "generation": generation, "status": status, "message": "新凭据仅展示一次；旧凭据立即失效。更新 Agent 后确认心跳，再恢复调度。"})
}

func (a *API) revokeHostCredential(w http.ResponseWriter, r *http.Request) {
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 503, "宿主身份服务暂不可用")
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), `UPDATE hosts SET status=CASE WHEN status='MAINTENANCE' THEN status ELSE 'CORDONED' END,updated_at=now() WHERE id=$1::uuid`, r.PathValue("id"))
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, 404, "宿主机不存在")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE host_credentials SET revoked_at=now(),updated_at=now() WHERE host_id=$1::uuid`, r.PathValue("id")); err != nil {
		writeError(w, 503, "吊销宿主凭据失败")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, 503, "吊销宿主凭据未完成，请重试")
		return
	}
	writeJSON(w, 200, map[string]any{"host_id": r.PathValue("id"), "revoked": true, "message": "凭据已吊销，宿主机停止新增调度；已有虚拟机未作变更"})
}
