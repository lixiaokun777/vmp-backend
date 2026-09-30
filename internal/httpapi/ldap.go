package httpapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var ldapAttributePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,63}$`)

type LDAPConfig struct {
	Configured      bool
	Active          bool
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
	return config.Active && config.URL != "" && config.BaseDN != "" && config.LoginFilter != ""
}

func (a *API) ldapStatus(w http.ResponseWriter, r *http.Request) {
	config, err := a.loadLDAPConfig(r.Context())
	if err != nil {
		writeError(w, 500, "读取 LDAP 配置失败："+err.Error())
		return
	}
	writeJSON(w, 200, ldapConfigResponse(config))
}

func (a *API) updateLDAPConfig(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled         bool   `json:"enabled"`
		URL             string `json:"url"`
		StartTLS        bool   `json:"start_tls"`
		BindDN          string `json:"bind_dn"`
		BindPassword    string `json:"bind_password"`
		ClearPassword   bool   `json:"clear_bind_password"`
		BaseDN          string `json:"base_dn"`
		LoginFilter     string `json:"login_filter"`
		SyncFilter      string `json:"sync_filter"`
		UsernameAttr    string `json:"username_attribute"`
		DisplayNameAttr string `json:"display_name_attribute"`
		EmailAttr       string `json:"email_attribute"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeError(w, 400, "LDAP 配置格式无效")
		return
	}
	config := LDAPConfig{
		Configured:      true,
		Active:          input.Enabled,
		URL:             strings.TrimSpace(input.URL),
		StartTLS:        input.StartTLS,
		BindDN:          strings.TrimSpace(input.BindDN),
		BaseDN:          strings.TrimSpace(input.BaseDN),
		LoginFilter:     strings.TrimSpace(input.LoginFilter),
		SyncFilter:      strings.TrimSpace(input.SyncFilter),
		UsernameAttr:    strings.TrimSpace(input.UsernameAttr),
		DisplayNameAttr: strings.TrimSpace(input.DisplayNameAttr),
		EmailAttr:       strings.TrimSpace(input.EmailAttr),
	}
	if err := validateLDAPConfig(config); err != nil {
		writeError(w, 422, err.Error())
		return
	}
	var encryptedPassword []byte
	if err := a.Service.DB.QueryRow(r.Context(), `SELECT bind_password_ciphertext FROM ldap_settings WHERE singleton=true`).Scan(&encryptedPassword); err != nil {
		writeError(w, 500, "读取 LDAP 密码配置失败")
		return
	}
	if input.ClearPassword {
		encryptedPassword = nil
	}
	if input.BindPassword != "" {
		var err error
		encryptedPassword, err = encryptSecret(a.SettingsEncryptionKey, []byte(input.BindPassword))
		if err != nil {
			writeError(w, 422, err.Error())
			return
		}
	}
	user, _ := userFromRequest(r)
	_, err := a.Service.DB.Exec(r.Context(), `UPDATE ldap_settings SET configured=true,enabled=$1,url=$2,start_tls=$3,bind_dn=$4,bind_password_ciphertext=$5,base_dn=$6,login_filter=$7,sync_filter=$8,username_attribute=$9,display_name_attribute=$10,email_attribute=$11,updated_by=$12,updated_at=now() WHERE singleton=true`, config.Active, config.URL, config.StartTLS, config.BindDN, encryptedPassword, config.BaseDN, config.LoginFilter, config.SyncFilter, config.UsernameAttr, config.DisplayNameAttr, config.EmailAttr, user.Username)
	if err != nil {
		writeError(w, 500, "保存 LDAP 配置失败："+err.Error())
		return
	}
	response := ldapConfigResponse(config)
	response["has_bind_password"] = len(encryptedPassword) > 0
	writeJSON(w, 200, response)
}

func (a *API) ldapTest(w http.ResponseWriter, r *http.Request) {
	config, err := a.loadLDAPConfig(r.Context())
	if err != nil {
		writeError(w, 500, "读取 LDAP 配置失败："+err.Error())
		return
	}
	if !config.Enabled() {
		writeError(w, 422, "LDAP 尚未启用或配置不完整")
		return
	}
	connection, err := openLDAP(config)
	if err != nil {
		writeError(w, 502, "连接 LDAP 失败："+err.Error())
		return
	}
	defer connection.Close()
	if config.BindDN != "" {
		if err := connection.Bind(config.BindDN, config.BindPassword); err != nil {
			writeError(w, 502, "LDAP 服务账号认证失败")
			return
		}
	}
	request := ldap.NewSearchRequest(config.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 8, false, "(objectClass=*)", []string{"dn"}, nil)
	if _, err := connection.Search(request); err != nil {
		writeError(w, 502, "LDAP Base DN 查询失败："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"connected": true, "message": "LDAP 连接和目录查询正常"})
}

func (a *API) ldapSync(w http.ResponseWriter, r *http.Request) {
	config, err := a.loadLDAPConfig(r.Context())
	if err != nil {
		writeError(w, 500, "读取 LDAP 配置失败："+err.Error())
		return
	}
	if !config.Enabled() {
		writeError(w, 422, "LDAP 尚未启用或配置不完整")
		return
	}
	connection, err := openLDAP(config)
	if err != nil {
		writeError(w, 502, "连接 LDAP 失败："+err.Error())
		return
	}
	defer connection.Close()
	if config.BindDN != "" {
		if err := connection.Bind(config.BindDN, config.BindPassword); err != nil {
			writeError(w, 502, "LDAP 服务账号认证失败")
			return
		}
	}
	filter := config.SyncFilter
	if filter == "" {
		filter = strings.ReplaceAll(config.LoginFilter, "%s", "*")
	}
	request := ldap.NewSearchRequest(config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 20, false, filter, []string{config.UsernameAttr, config.DisplayNameAttr, config.EmailAttr}, nil)
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
		username := strings.TrimSpace(entry.GetAttributeValue(config.UsernameAttr))
		if !usernamePattern.MatchString(username) {
			skipped++
			continue
		}
		displayName := strings.TrimSpace(entry.GetAttributeValue(config.DisplayNameAttr))
		email := strings.TrimSpace(entry.GetAttributeValue(config.EmailAttr))
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

func (a *API) authenticateLDAP(ctx context.Context, userDN, password string) error {
	config, err := a.loadLDAPConfig(ctx)
	if err != nil {
		return err
	}
	if !config.Enabled() || userDN == "" || password == "" {
		return errors.New("LDAP 未配置或用户 DN 无效")
	}
	connection, err := openLDAP(config)
	if err != nil {
		return err
	}
	defer connection.Close()
	return connection.Bind(userDN, password)
}

func (a *API) loadLDAPConfig(ctx context.Context) (LDAPConfig, error) {
	config := a.LDAP
	var encryptedPassword []byte
	err := a.Service.DB.QueryRow(ctx, `SELECT configured,enabled,url,start_tls,bind_dn,bind_password_ciphertext,base_dn,login_filter,sync_filter,username_attribute,display_name_attribute,email_attribute FROM ldap_settings WHERE singleton=true`).Scan(&config.Configured, &config.Active, &config.URL, &config.StartTLS, &config.BindDN, &encryptedPassword, &config.BaseDN, &config.LoginFilter, &config.SyncFilter, &config.UsernameAttr, &config.DisplayNameAttr, &config.EmailAttr)
	if err != nil {
		return LDAPConfig{}, err
	}
	if !config.Configured {
		return a.LDAP, nil
	}
	if len(encryptedPassword) > 0 {
		password, err := decryptSecret(a.SettingsEncryptionKey, encryptedPassword)
		if err != nil {
			return LDAPConfig{}, errors.New("LDAP 绑定密码无法解密，请检查配置加密密钥")
		}
		config.BindPassword = string(password)
	}
	return config, nil
}

func ldapConfigResponse(config LDAPConfig) map[string]any {
	return map[string]any{
		"configured":             config.Configured,
		"enabled":                config.Enabled(),
		"requested_enabled":      config.Active,
		"url":                    config.URL,
		"start_tls":              config.StartTLS,
		"bind_dn":                config.BindDN,
		"has_bind_password":      config.BindPassword != "",
		"base_dn":                config.BaseDN,
		"login_filter":           config.LoginFilter,
		"sync_filter":            config.SyncFilter,
		"username_attribute":     config.UsernameAttr,
		"display_name_attribute": config.DisplayNameAttr,
		"email_attribute":        config.EmailAttr,
	}
}

func validateLDAPConfig(config LDAPConfig) error {
	if config.URL == "" && config.BaseDN == "" && !config.Active {
		return nil
	}
	parsed, err := url.Parse(config.URL)
	if err != nil || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") || parsed.Host == "" {
		return errors.New("LDAP 地址必须是有效的 ldap:// 或 ldaps:// 地址")
	}
	if config.BaseDN == "" {
		return errors.New("Base DN 不能为空")
	}
	if !strings.Contains(config.LoginFilter, "%s") {
		return errors.New("登录过滤器必须包含 %s 用户名占位符")
	}
	if config.SyncFilter == "" {
		return errors.New("同步过滤器不能为空")
	}
	for name, value := range map[string]string{"用户名属性": config.UsernameAttr, "显示名称属性": config.DisplayNameAttr, "邮箱属性": config.EmailAttr} {
		if !ldapAttributePattern.MatchString(value) {
			return fmt.Errorf("%s格式无效", name)
		}
	}
	return nil
}

func openLDAP(config LDAPConfig) (*ldap.Conn, error) {
	parsed, err := url.Parse(config.URL)
	if err != nil || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") {
		return nil, errors.New("LDAP URL 必须使用 ldap:// 或 ldaps://")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()}
	connection, err := ldap.DialURL(config.URL, ldap.DialWithDialer(&netDialer), ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}
	if config.StartTLS && parsed.Scheme == "ldap" {
		if err := connection.StartTLS(tlsConfig); err != nil {
			connection.Close()
			return nil, err
		}
	}
	return connection, nil
}

func encryptSecret(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("未配置有效的 SETTINGS_ENCRYPTION_KEY，无法保存 LDAP 密码")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptSecret(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("配置加密密钥无效")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("密文长度无效")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], nil)
}

var netDialer = net.Dialer{Timeout: 8 * time.Second}

func ldapLoginFilter(template, username string) (string, error) {
	if !strings.Contains(template, "%s") {
		return "", fmt.Errorf("LDAP 登录过滤器必须包含 %%s")
	}
	return fmt.Sprintf(template, ldap.EscapeFilter(username)), nil
}
