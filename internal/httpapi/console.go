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
	expiresAt := time.Now().Add(2 * time.Minute)
	ticket := consoleTicket{SessionID: base64.RawURLEncoding.EncodeToString(sessionBytes), HostID: hostID, Instance: r.PathValue("id"), Domain: name, Mode: input.Mode, Actor: user.Username, ExpiresAt: expiresAt.Unix()}
	signed, err := signConsoleTicket(ticket, a.ConsoleSigningKey)
	if err != nil {
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
