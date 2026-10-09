package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"vmp-backend/internal/platform"
)

func TestConsoleProxySameOriginOwnerAndReplay(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	key := []byte("Isolated-Console-Proxy-Key-Only-2026")
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ticket, err := verifyConsoleTicket(r.URL.Query().Get("ticket"), key)
		if err != nil {
			w.WriteHeader(401)
			return
		}
		tag, err := db.Exec(r.Context(), `UPDATE console_sessions SET used_at=now() WHERE id=$1 AND used_at IS NULL AND expires_at>now()`, ticket.SessionID)
		if err != nil || tag.RowsAffected() != 1 {
			w.WriteHeader(409)
			return
		}
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			kind, data, err := c.Read(r.Context())
			if err != nil || c.Write(r.Context(), kind, data) != nil {
				return
			}
		}
	}))
	defer agent.Close()
	var userID, hostID, appID, instanceID string
	if err := db.QueryRow(ctx, `INSERT INTO users(username,password_hash) VALUES('console-owner','hash') RETURNING id::text`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	token := "Isolated-Console-Owner-Session"
	hash := sha256.Sum256([]byte(token))
	if _, err := db.Exec(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2::uuid,now()+interval '1 hour')`, hash[:], userID); err != nil {
		t.Fatal(err)
	}
	facts, _ := json.Marshal(map[string]any{"host": map[string]string{"console_url": strings.Replace(agent.URL, "http://", "ws://", 1)}})
	if err := db.QueryRow(ctx, `INSERT INTO hosts(name,status,management_ip,agent_mode,allocatable_cpu,allocatable_memory_mb,allocatable_disk_gb,agent_allocatable_cpu,agent_allocatable_memory_mb,agent_allocatable_disk_gb,facts) VALUES('console-proxy-host','ACTIVE','127.0.0.1','kvm',8,8192,100,8,8192,100,$1) RETURNING id::text`, facts).Scan(&hostID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO host_credentials(host_id,token_hash,generation) VALUES($1::uuid,$2,1)`, hostID, hash[:]); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO applications(request_no,applicant,instance_name,purpose,flavor_id,image_id,lease_hours,status) VALUES('console-proxy-test','console-owner','console-proxy-vm','test','c1m2','ubuntu-2204',1,'APPROVED') RETURNING id::text`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO instances(application_id,host_id,name,lifecycle_status,expires_at,allocated_cpu,allocated_memory_mb,allocated_disk_gb,flavor_name_snapshot) VALUES($1::uuid,$2::uuid,'console-proxy-vm','ERROR',now()+interval '1 hour',1,2048,40,'轻量型') RETURNING id::text`, appID, hostID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO discovered_instances(host_id,provider_uuid,name,state,ownership,platform_instance_id) VALUES($1::uuid,'test-provider','console-proxy-vm','running','MANAGED',$2::uuid)`, hostID, instanceID); err != nil {
		t.Fatal(err)
	}
	a := &API{Service: &platform.Service{DB: db}, ConsoleSigningKey: key}
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	ticket := consoleTicket{SessionID: "proxy-isolated-once", HostID: hostID, Instance: instanceID, Domain: "console-proxy-vm", Mode: "serial", Actor: "console-owner", ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
	if _, err := db.Exec(ctx, `INSERT INTO console_sessions(id,host_id,instance_id,domain,mode,actor,expires_at) VALUES($1,$2::uuid,$3::uuid,$4,$5,$6,to_timestamp($7))`, ticket.SessionID, hostID, instanceID, ticket.Domain, ticket.Mode, ticket.Actor, ticket.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	signed, _ := signConsoleTicket(ticket, key)
	endpoint := strings.Replace(server.URL, "http://", "ws://", 1) + "/api/v1/console/serial?ticket=" + url.QueryEscape(signed)
	options := &websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{server.URL}, "Cookie": []string{sessionCookieName + "=" + token}}}
	bad := &websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{"https://untrusted.example"}, "Cookie": options.HTTPHeader["Cookie"]}}
	if c, response, err := websocket.Dial(ctx, endpoint, bad); err == nil || response.StatusCode != 403 {
		if c != nil {
			c.CloseNow()
		}
		t.Fatal("跨源连接未拒绝", err)
	}
	connection, response, err := websocket.Dial(ctx, endpoint, options)
	if err != nil {
		t.Fatal("授权错误现场不能通过同源桥连接", err, response)
	}
	defer connection.CloseNow()
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = connection.Write(deadline, websocket.MessageBinary, []byte("救援测试")); err != nil {
		t.Fatal(err)
	}
	_, data, err := connection.Read(deadline)
	if err != nil || string(data) != "救援测试" {
		t.Fatal("双向控制台桥失败", err)
	}
	if c, response, err := websocket.Dial(ctx, endpoint, options); err == nil || response.StatusCode != 409 {
		if c != nil {
			c.CloseNow()
		}
		t.Fatal("已使用票据允许重放", err)
	}
	connection.CloseNow()
	if _, err := db.Exec(ctx, `UPDATE console_sessions SET used_at=NULL; UPDATE instances SET lifecycle_status='RETAINED'`); err != nil {
		t.Fatal(err)
	}
	if c, response, err := websocket.Dial(ctx, endpoint, options); err == nil || response.StatusCode != 409 {
		if c != nil {
			c.CloseNow()
		}
		t.Fatal("保留期通过救援接入", err)
	}
}

func TestVerifyConsoleTicketRejectsChangesAndOversizedPayload(t *testing.T) {
	key := []byte("Isolated-Console-Proxy-Key-Only-2026")
	valid, _ := signConsoleTicket(consoleTicket{SessionID: "test", ExpiresAt: time.Now().Add(time.Minute).Unix()}, key)
	if _, err := verifyConsoleTicket(valid, key); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{valid + "x", strings.Repeat("a", 5000), "invalid", "x.y"} {
		if _, err := verifyConsoleTicket(value, key); err == nil {
			t.Fatal("接受了无效控制台票据")
		}
	}
}
