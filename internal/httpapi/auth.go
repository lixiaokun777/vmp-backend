package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const sessionCookieName = "vmp_session"

type authContextKey struct{}

type AuthUser struct {
	ID                 string `json:"id"`
	Username           string `json:"username"`
	DisplayName        string `json:"display_name"`
	Email              string `json:"email"`
	Role               string `json:"role"`
	Source             string `json:"source"`
	MustChangePassword bool   `json:"must_change_password"`
}

func userFromRequest(r *http.Request) (AuthUser, bool) {
	user, ok := r.Context().Value(authContextKey{}).(AuthUser)
	return user, ok
}

func (a *API) authLogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Source   string `json:"source"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		a.recordAudit(r.Context(), r, "anonymous", "auth.login", "session", "-", "FAILED", map[string]any{"reason": "invalid_json"})
		writeError(w, 400, "登录信息格式无效")
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	input.Source = strings.ToUpper(strings.TrimSpace(input.Source))
	if input.Source == "" {
		input.Source = "LOCAL"
	}
	if input.Source != "LOCAL" && input.Source != "LDAP" {
		a.recordAudit(r.Context(), r, input.Username, "auth.login", "session", input.Username, "FAILED", map[string]any{"source": input.Source, "reason": "invalid_source"})
		writeError(w, 422, "登录类型无效")
		return
	}
	if input.Username == "" || input.Password == "" {
		a.recordAudit(r.Context(), r, input.Username, "auth.login", "session", input.Username, "FAILED", map[string]any{"source": input.Source, "reason": "missing_credentials"})
		writeError(w, 422, "请输入用户名和密码")
		return
	}
	var user AuthUser
	var enabled bool
	var passwordOK bool
	var ldapDN string
	err := a.Service.DB.QueryRow(r.Context(), `SELECT id::text,username,display_name,email,role,source,enabled,must_change_password,coalesce(ldap_dn,''),CASE WHEN source='LOCAL' THEN password_hash=crypt($2,password_hash) ELSE false END FROM users WHERE lower(username)=lower($1) AND source=$3`, input.Username, input.Password, input.Source).Scan(&user.ID, &user.Username, &user.DisplayName, &user.Email, &user.Role, &user.Source, &enabled, &user.MustChangePassword, &ldapDN, &passwordOK)
	if err != nil || !enabled {
		a.recordAudit(r.Context(), r, input.Username, "auth.login", "session", input.Username, "FAILED", map[string]any{"source": input.Source, "reason": "invalid_credentials_or_disabled"})
		writeError(w, 401, "用户名或密码错误")
		return
	}
	if user.Source == "LDAP" {
		if err := a.authenticateLDAP(r.Context(), ldapDN, input.Password); err != nil {
			a.recordAudit(r.Context(), r, input.Username, "auth.login", "session", input.Username, "FAILED", map[string]any{"source": input.Source, "reason": "invalid_credentials"})
			writeError(w, 401, "用户名或密码错误")
			return
		}
	} else if !passwordOK {
		a.recordAudit(r.Context(), r, input.Username, "auth.login", "session", input.Username, "FAILED", map[string]any{"source": input.Source, "reason": "invalid_credentials"})
		writeError(w, 401, "用户名或密码错误")
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeError(w, 500, "无法创建登录会话")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256([]byte(token))
	expiresAt := time.Now().Add(a.SessionTTL)
	remoteAddress := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		remoteAddress = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if _, err := a.Service.DB.Exec(r.Context(), `INSERT INTO user_sessions(token_hash,user_id,expires_at,remote_address,user_agent) VALUES($1,$2::uuid,$3,$4,$5)`, tokenHash[:], user.ID, expiresAt, remoteAddress, r.UserAgent()); err != nil {
		writeError(w, 500, "无法创建登录会话")
		return
	}
	_, _ = a.Service.DB.Exec(r.Context(), `UPDATE users SET last_login_at=now(),updated_at=now() WHERE id=$1::uuid`, user.ID)
	a.recordAudit(r.Context(), r, user.Username, "auth.login", "user", user.ID, "SUCCESS", map[string]any{"source": user.Source})
	a.setSessionCookie(w, token, expiresAt)
	writeJSON(w, 200, map[string]any{"user": user, "expires_at": expiresAt})
}

func (a *API) authLogout(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		hash := sha256.Sum256([]byte(cookie.Value))
		_, _ = a.Service.DB.Exec(r.Context(), `DELETE FROM user_sessions WHERE token_hash=$1`, hash[:])
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true, Secure: a.SessionSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(0, 0)})
	a.recordAudit(r.Context(), r, user.Username, "auth.logout", "user", user.ID, "SUCCESS", map[string]any{})
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) authMe(w http.ResponseWriter, r *http.Request) {
	user, ok := userFromRequest(r)
	if !ok {
		writeError(w, 401, "未登录")
		return
	}
	writeJSON(w, 200, map[string]any{"user": user})
}

func (a *API) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	if user.Source != "LOCAL" {
		writeError(w, 422, "LDAP 用户必须在目录服务中修改密码")
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeError(w, 400, "密码信息格式无效")
		return
	}
	if err := validatePassword(input.NewPassword); err != nil {
		writeError(w, 422, err.Error())
		return
	}
	var currentOK bool
	if err := a.Service.DB.QueryRow(r.Context(), `SELECT password_hash=crypt($2,password_hash) FROM users WHERE id=$1::uuid`, user.ID, input.CurrentPassword).Scan(&currentOK); err != nil || !currentOK {
		writeError(w, 422, "当前密码错误")
		return
	}
	if _, err := a.Service.DB.Exec(r.Context(), `UPDATE users SET password_hash=crypt($2,gen_salt('bf',12)),must_change_password=false,updated_at=now() WHERE id=$1::uuid`, user.ID, input.NewPassword); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		currentHash := sha256.Sum256([]byte(cookie.Value))
		_, _ = a.Service.DB.Exec(r.Context(), `DELETE FROM user_sessions WHERE user_id=$1::uuid AND token_hash<>$2`, user.ID, currentHash[:])
	}
	a.recordAudit(r.Context(), r, user.Username, "auth.password.change", "user", user.ID, "SUCCESS", map[string]any{})
	writeJSON(w, 200, map[string]any{"updated": true})
}

func (a *API) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", HttpOnly: true, Secure: a.SessionSecure, SameSite: http.SameSiteStrictMode, Expires: expiresAt, MaxAge: int(time.Until(expiresAt).Seconds())})
}

func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" || r.URL.Path == "/api/v1/auth/login" || strings.HasPrefix(r.URL.Path, "/api/v1/agents/") {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, 401, "登录已失效，请重新登录")
			return
		}
		hash := sha256.Sum256([]byte(cookie.Value))
		var user AuthUser
		err = a.Service.DB.QueryRow(r.Context(), `SELECT u.id::text,u.username,u.display_name,u.email,u.role,u.source,u.must_change_password FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.enabled`, hash[:]).Scan(&user.ID, &user.Username, &user.DisplayName, &user.Email, &user.Role, &user.Source, &user.MustChangePassword)
		if err != nil {
			writeError(w, 401, "登录已失效，请重新登录")
			return
		}
		_, _ = a.Service.DB.Exec(r.Context(), `UPDATE user_sessions SET last_seen_at=now() WHERE token_hash=$1 AND last_seen_at<now()-interval '5 minutes'`, hash[:])
		if user.MustChangePassword && r.URL.Path != "/api/v1/auth/me" && r.URL.Path != "/api/v1/auth/password" && r.URL.Path != "/api/v1/auth/logout" {
			writeError(w, 403, "首次登录必须先修改密码")
			return
		}
		if user.Role != "ADMIN" && !ordinaryUserRouteAllowed(r) {
			writeError(w, 403, "当前账号没有管理员权限")
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ordinaryUserRouteAllowed(r *http.Request) bool {
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/v1/auth/") {
		return true
	}
	if r.Method == http.MethodGet && (path == "/api/v1/flavors" || path == "/api/v1/images" || path == "/api/v1/networks" || path == "/api/v1/instances" || path == "/api/v1/approvals") {
		return true
	}
	if path == "/api/v1/applications" && r.Method == http.MethodPost {
		return true
	}
	if strings.HasPrefix(path, "/api/v1/instances/") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/instances/"), "/")
		if r.Method == http.MethodGet && len(parts) == 1 && parts[0] != "" {
			return true
		}
		if r.Method == http.MethodPost && len(parts) == 2 && parts[0] != "" && (parts[1] == "actions" || parts[1] == "renew" || parts[1] == "restore") {
			return true
		}
		if r.Method == http.MethodPost && len(parts) == 2 && parts[0] != "" && parts[1] == "console-sessions" {
			return true
		}
	}
	return false
}

func validatePassword(password string) error {
	if len(password) < 10 {
		return errors.New("密码不能少于 10 个字符")
	}
	var upper, lower, digit bool
	for _, value := range password {
		upper = upper || value >= 'A' && value <= 'Z'
		lower = lower || value >= 'a' && value <= 'z'
		digit = digit || value >= '0' && value <= '9'
	}
	if !upper || !lower || !digit {
		return errors.New("密码必须同时包含大写字母、小写字母和数字")
	}
	return nil
}
