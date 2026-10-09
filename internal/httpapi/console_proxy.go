package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

var consoleConnections = struct {
	sync.Mutex
	total int
	users map[string]int
}{users: make(map[string]int)}

func reserveConsoleConnection(userID string) (func(), bool) {
	consoleConnections.Lock()
	defer consoleConnections.Unlock()
	if consoleConnections.total >= 64 || consoleConnections.users[userID] >= 4 {
		return nil, false
	}
	consoleConnections.total++
	consoleConnections.users[userID]++
	return func() {
		consoleConnections.Lock()
		defer consoleConnections.Unlock()
		consoleConnections.total--
		consoleConnections.users[userID]--
		if consoleConnections.users[userID] == 0 {
			delete(consoleConnections.users, userID)
		}
	}, true
}

func verifyConsoleTicket(value string, key []byte) (consoleTicket, error) {
	var ticket consoleTicket
	parts := strings.Split(value, ".")
	if len(key) < 32 || len(value) > 4096 || len(parts) != 2 {
		return ticket, errors.New("控制台票据无效")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(mac.Sum(nil), signature) {
		return ticket, errors.New("控制台票据签名无效")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(payload, &ticket) != nil || ticket.ExpiresAt <= time.Now().Unix() || ticket.ExpiresAt > time.Now().Add(6*time.Minute).Unix() || ticket.SessionID == "" {
		return ticket, errors.New("票据已失效，请点击右上角「重新连接」")
	}
	return ticket, nil
}

// 浏览器仅连接平台同源；目标地址从授权宿主记录取得，并固定拨号其纳管 IP。
func (a *API) consoleProxy(w http.ResponseWriter, r *http.Request) {
	u, ok := userFromRequest(r)
	if !ok {
		writeError(w, 401, "登录已失效，请重新登录")
		return
	}
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || !strings.EqualFold(origin.Host, r.Host) || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		writeError(w, 403, "不允许跨来源打开控制台")
		return
	}
	ticket, err := verifyConsoleTicket(r.URL.Query().Get("ticket"), a.ConsoleSigningKey)
	if err != nil || ticket.Actor != u.Username || ticket.Mode != r.PathValue("mode") || (ticket.Mode != "vnc" && ticket.Mode != "serial") {
		writeError(w, 409, "票据已失效，请点击右上角「重新连接」")
		return
	}
	var consoleURL, managementIP string
	var leaseEnd time.Time
	err = a.Service.DB.QueryRow(r.Context(), `SELECT coalesce(h.facts#>>'{host,console_url}',''),host(h.management_ip),i.expires_at FROM console_sessions s JOIN instances i ON i.id=s.instance_id JOIN applications ap ON ap.id=i.application_id JOIN hosts h ON h.id=i.host_id JOIN host_credentials hc ON hc.host_id=h.id AND hc.revoked_at IS NULL WHERE s.id=$1 AND s.actor=$2 AND s.mode=$3 AND s.host_id::text=$4 AND s.instance_id::text=$5 AND s.domain=$6 AND s.used_at IS NULL AND s.expires_at>now() AND (ap.applicant=$2 OR $7) AND i.expires_at>now() AND i.lifecycle_status IN ('RUNNING','PROVISIONING','ERROR','STOPPED') AND EXISTS(SELECT 1 FROM discovered_instances d WHERE d.host_id=i.host_id AND d.platform_instance_id=i.id AND d.name=i.name AND d.ownership='MANAGED' AND d.last_seen_at>now()-interval '120 seconds' AND (i.provider_ref IS NULL OR i.provider_ref=d.provider_uuid) AND lower(replace(d.state,' ','_')) IN ('running','paused','blocked','pmsuspended'))`, ticket.SessionID, u.Username, ticket.Mode, ticket.HostID, ticket.Instance, ticket.Domain, u.Role == "ADMIN").Scan(&consoleURL, &managementIP, &leaseEnd)
	if err != nil {
		writeError(w, 409, "票据已失效或托管域不可用，请点击右上角「重新连接」")
		return
	}
	ip, ipErr := netip.ParseAddr(managementIP)
	endpoint, err := url.Parse(consoleURL)
	if err != nil || ipErr != nil || ip.IsUnspecified() || ip.IsMulticast() || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Scheme != "ws" && endpoint.Scheme != "wss") {
		writeError(w, 503, "宿主控制台地址或纳管 IP 配置无效")
		return
	}
	port := endpoint.Port()
	if port == "" {
		port = "80"
		if endpoint.Scheme == "wss" {
			port = "443"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		writeError(w, 503, "宿主控制台端口无效")
		return
	}
	release, ok := reserveConsoleConnection(u.ID)
	if !ok {
		writeError(w, 429, "控制台连接数已达上限，请关闭其他控制台后重试")
		return
	}
	defer release()
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/console/" + ticket.Mode
	query := url.Values{}
	query.Set("ticket", r.URL.Query().Get("ticket"))
	endpoint.RawQuery = query.Encode()
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 10 * time.Second, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("控制台不允许重定向") }}
	dialCtx, dialCancel := context.WithTimeout(r.Context(), 10*time.Second)
	upstream, response, err := websocket.Dial(dialCtx, endpoint.String(), &websocket.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Origin": []string{r.Header.Get("Origin")}}, CompressionMode: websocket.CompressionDisabled})
	dialCancel()
	if err != nil {
		if response != nil && (response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 409) {
			writeError(w, 409, "票据已失效，请点击右上角「重新连接」")
		} else {
			writeError(w, 502, "暂时无法连接宿主控制台，请重新连接或联系管理员")
		}
		return
	}
	defer upstream.CloseNow()
	downstream, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer downstream.CloseNow()
	upstream.SetReadLimit(2 << 20)
	downstream.SetReadLimit(2 << 20)
	deadline := time.Now().Add(24 * time.Hour)
	if leaseEnd.Before(deadline) {
		deadline = leaseEnd
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	finished := make(chan error, 2)
	copyMessages := func(dst, src *websocket.Conn) {
		for {
			kind, data, readErr := src.Read(ctx)
			if readErr != nil {
				finished <- readErr
				return
			}
			if writeErr := dst.Write(ctx, kind, data); writeErr != nil {
				finished <- writeErr
				return
			}
		}
	}
	go copyMessages(upstream, downstream)
	go copyMessages(downstream, upstream)
	defer func() {
		cancel()
		upstream.CloseNow()
		downstream.CloseNow()
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-finished:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			cookie, cookieErr := r.Cookie(sessionCookieName)
			var active bool
			if cookieErr != nil {
				return
			}
			hash := sha256.Sum256([]byte(cookie.Value))
			checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
			checkErr := a.Service.DB.QueryRow(checkCtx, `SELECT EXISTS(SELECT 1 FROM user_sessions s JOIN users u ON u.id=s.user_id JOIN instances i ON i.id=$2::uuid JOIN applications ap ON ap.id=i.application_id JOIN host_credentials hc ON hc.host_id=i.host_id WHERE s.token_hash=$1 AND u.id::text=$3 AND s.expires_at>now() AND u.enabled AND NOT u.must_change_password AND (u.source<>'LDAP' OR u.ldap_directory_present) AND (u.role='ADMIN' OR ap.applicant=u.username) AND hc.revoked_at IS NULL AND i.expires_at>now() AND i.lifecycle_status IN ('RUNNING','PROVISIONING','ERROR','STOPPED'))`, hash[:], ticket.Instance, u.ID).Scan(&active)
			checkCancel()
			if checkErr != nil || !active {
				return
			}
		}
	}
}
