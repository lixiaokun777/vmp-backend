package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type consoleTicket struct {
	SessionID string `json:"session_id"`
	HostID    string `json:"host_id"`
	Instance  string `json:"instance_id"`
	Domain    string `json:"domain"`
	Mode      string `json:"mode"`
	Actor     string `json:"actor"`
	ExpiresAt int64  `json:"expires_at"`
}

func (a *API) createConsoleSession(w http.ResponseWriter, r *http.Request) {
	if len(a.ConsoleSigningKey) < 32 {
		writeError(w, 503, "控制台签名密钥未配置")
		return
	}
	var input struct {
		Mode string `json:"mode"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeError(w, 400, "控制台请求格式无效")
		return
	}
	input.Mode = strings.ToLower(strings.TrimSpace(input.Mode))
	if input.Mode != "vnc" && input.Mode != "serial" {
		writeError(w, 422, "控制台类型仅支持 vnc 或 serial")
		return
	}
	user, _ := userFromRequest(r)
	var name, lifecycleStatus, hostID, consoleURL string
	err := a.Service.DB.QueryRow(r.Context(), `SELECT i.name,i.lifecycle_status,h.id::text,coalesce(h.facts#>>'{host,console_url}','') FROM instances i JOIN applications ap ON ap.id=i.application_id JOIN hosts h ON h.id=i.host_id WHERE i.id=$1::uuid AND ($3 OR ap.applicant=$2)`, r.PathValue("id"), user.Username, user.Role == "ADMIN").Scan(&name, &lifecycleStatus, &hostID, &consoleURL)
	if err != nil {
		writeError(w, 404, "实例不存在")
		return
	}
	if lifecycleStatus != "RUNNING" {
		writeError(w, 409, "只有运行中的实例可以打开控制台")
		return
	}
	endpoint, err := url.Parse(consoleURL)
	if err != nil || (endpoint.Scheme != "ws" && endpoint.Scheme != "wss") || endpoint.Host == "" {
		writeError(w, 503, "宿主机 Agent 未上报可用的控制台地址")
		return
	}
	sessionBytes := make([]byte, 18)
	if _, err := rand.Read(sessionBytes); err != nil {
		writeError(w, 500, "无法创建控制台会话")
		return
	}
	// 五分钟用于覆盖弹窗放行和人工操作延迟；真正的安全边界由服务端一次性核销保证。
	expiresAt := time.Now().Add(5 * time.Minute)
	ticket := consoleTicket{SessionID: base64.RawURLEncoding.EncodeToString(sessionBytes), HostID: hostID, Instance: r.PathValue("id"), Domain: name, Mode: input.Mode, Actor: user.Username, ExpiresAt: expiresAt.Unix()}
	_, _ = a.Service.DB.Exec(r.Context(), `DELETE FROM console_sessions WHERE expires_at<now()-interval '1 day'`)
	if _, err := a.Service.DB.Exec(r.Context(), `INSERT INTO console_sessions(id,host_id,instance_id,domain,mode,actor,expires_at) VALUES($1,$2::uuid,$3::uuid,$4,$5,$6,$7)`, ticket.SessionID, hostID, ticket.Instance, ticket.Domain, ticket.Mode, ticket.Actor, expiresAt); err != nil {
		writeError(w, 500, "无法保存控制台会话")
		return
	}
	signed, err := signConsoleTicket(ticket, a.ConsoleSigningKey)
	if err != nil {
		_, _ = a.Service.DB.Exec(r.Context(), `DELETE FROM console_sessions WHERE id=$1 AND used_at IS NULL`, ticket.SessionID)
		writeError(w, 500, err.Error())
		return
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/console/" + input.Mode
	values := endpoint.Query()
	values.Set("ticket", signed)
	endpoint.RawQuery = values.Encode()
	a.recordAudit(r.Context(), r, user.Username, "instance.console.open", "instance", r.PathValue("id"), "SUCCESS", map[string]any{"mode": input.Mode, "session_id": ticket.SessionID, "expires_at": expiresAt})
	writeJSON(w, 201, map[string]any{"session_id": ticket.SessionID, "mode": input.Mode, "websocket_url": endpoint.String(), "expires_at": expiresAt})
}

// consumeConsoleSession 由目标宿主机 Agent 在 WebSocket 升级前调用，原子核销一次性票据。
func (a *API) consumeConsoleSession(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAgent(w, r) {
		return
	}
	var input struct {
		Mode   string `json:"mode"`
		Domain string `json:"domain"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	var sessionID string
	err := a.Service.DB.QueryRow(r.Context(), `UPDATE console_sessions SET used_at=now() WHERE id=$1 AND host_id=$2::uuid AND mode=$3 AND domain=$4 AND used_at IS NULL AND expires_at>now() RETURNING id`, r.PathValue("sessionID"), r.PathValue("id"), input.Mode, input.Domain).Scan(&sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 409, "控制台票据已使用或已过期")
		return
	}
	if err != nil {
		writeError(w, 500, "无法核销控制台票据")
		return
	}
	writeJSON(w, 200, map[string]any{"consumed": true})
}

func signConsoleTicket(ticket consoleTicket, key []byte) (string, error) {
	payload, err := json.Marshal(ticket)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if encoded == "" || signature == "" {
		return "", errors.New("无法签发控制台票据")
	}
	return encoded + "." + signature, nil
}
