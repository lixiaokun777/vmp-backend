package httpapi

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LDAPConfig struct {
	URL             string
	BindDN          string
	BindPassword    string
	BaseDN          string
	LoginFilter     string
	SyncFilter      string
	UsernameAttr    string
	DisplayNameAttr string
	EmailAttr       string
	StartTLS        bool
}

func (config LDAPConfig) Enabled() bool {
	return config.URL != "" && config.BaseDN != "" && config.LoginFilter != ""
}

func (a *API) ldapStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"enabled":            a.LDAP.Enabled(),
		"url":                a.LDAP.URL,
		"base_dn":            a.LDAP.BaseDN,
		"login_filter":       a.LDAP.LoginFilter,
		"sync_filter":        a.LDAP.SyncFilter,
		"username_attribute": a.LDAP.UsernameAttr,
	})
}

func (a *API) ldapSync(w http.ResponseWriter, r *http.Request) {
	if !a.LDAP.Enabled() {
		writeError(w, 422, "LDAP 尚未配置")
		return
	}
	connection, err := a.openLDAP()
	if err != nil {
		writeError(w, 502, "连接 LDAP 失败："+err.Error())
		return
	}
	defer connection.Close()
	if a.LDAP.BindDN != "" {
		if err := connection.Bind(a.LDAP.BindDN, a.LDAP.BindPassword); err != nil {
			writeError(w, 502, "LDAP 服务账号认证失败")
			return
		}
	}
	filter := a.LDAP.SyncFilter
	if filter == "" {
		filter = strings.ReplaceAll(a.LDAP.LoginFilter, "%s", "*")
	}
	request := ldap.NewSearchRequest(a.LDAP.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 20, false, filter, []string{a.LDAP.UsernameAttr, a.LDAP.DisplayNameAttr, a.LDAP.EmailAttr}, nil)
	result, err := connection.Search(request)
	if err != nil {
		writeError(w, 502, "LDAP 用户查询失败："+err.Error())
		return
	}
	tx, err := a.Service.DB.Begin(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	synced := 0
	skipped := 0
	syncedUsernames := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		username := strings.TrimSpace(entry.GetAttributeValue(a.LDAP.UsernameAttr))
		if !usernamePattern.MatchString(username) {
			skipped++
			continue
		}
		displayName := strings.TrimSpace(entry.GetAttributeValue(a.LDAP.DisplayNameAttr))
		email := strings.TrimSpace(entry.GetAttributeValue(a.LDAP.EmailAttr))
		tag, err := tx.Exec(r.Context(), `INSERT INTO users(username,display_name,email,role,source,ldap_dn,enabled) VALUES($1,$2,$3,'USER','LDAP',$4,true) ON CONFLICT (lower(username)) DO UPDATE SET display_name=excluded.display_name,email=excluded.email,ldap_dn=excluded.ldap_dn,enabled=true,updated_at=now() WHERE users.source='LDAP'`, username, displayName, email, entry.DN)
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		if tag.RowsAffected() > 0 {
			synced++
			syncedUsernames = append(syncedUsernames, strings.ToLower(username))
		} else {
			skipped++
		}
	}
	if _, err := tx.Exec(r.Context(), `UPDATE users SET enabled=false,updated_at=now() WHERE source='LDAP' AND NOT (lower(username)=ANY($1::text[]))`, syncedUsernames); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM user_sessions WHERE user_id IN (SELECT id FROM users WHERE source='LDAP' AND NOT enabled)`); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"synced": synced, "skipped": skipped, "found": len(result.Entries)})
}

func (a *API) authenticateLDAP(userDN, password string) error {
	if !a.LDAP.Enabled() || userDN == "" || password == "" {
		return errors.New("LDAP 未配置或用户 DN 无效")
	}
	connection, err := a.openLDAP()
	if err != nil {
		return err
	}
	defer connection.Close()
	return connection.Bind(userDN, password)
}

func (a *API) openLDAP() (*ldap.Conn, error) {
	parsed, err := url.Parse(a.LDAP.URL)
	if err != nil || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") {
		return nil, errors.New("LDAP URL 必须使用 ldap:// 或 ldaps://")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()}
	connection, err := ldap.DialURL(a.LDAP.URL, ldap.DialWithDialer(&netDialer), ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}
	if a.LDAP.StartTLS && parsed.Scheme == "ldap" {
		if err := connection.StartTLS(tlsConfig); err != nil {
			connection.Close()
			return nil, err
		}
	}
	return connection, nil
}

var netDialer = net.Dialer{Timeout: 8 * time.Second}

func ldapLoginFilter(template, username string) (string, error) {
	if !strings.Contains(template, "%s") {
		return "", fmt.Errorf("LDAP 登录过滤器必须包含 %%s")
	}
	return fmt.Sprintf(template, ldap.EscapeFilter(username)), nil
}
