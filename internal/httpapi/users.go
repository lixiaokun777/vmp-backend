package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{2,64}$`)

func (a *API) users(w http.ResponseWriter, r *http.Request) {
	a.queryList(w, r, `SELECT jsonb_build_object('id',id,'username',username,'display_name',display_name,'email',email,'role',role,'source',source,'enabled',enabled,'ldap_directory_present',ldap_directory_present,'must_change_password',must_change_password,'last_login_at',last_login_at,'created_at',created_at) FROM users ORDER BY role,username`)
}

func (a *API) createLocalUser(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Role        string `json:"role"`
		Password    string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeError(w, 400, "用户信息格式无效")
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	input.Role = strings.ToUpper(strings.TrimSpace(input.Role))
	if !usernamePattern.MatchString(input.Username) || (input.Role != "ADMIN" && input.Role != "USER") {
		writeError(w, 422, "用户名或角色无效")
		return
	}
	if err := validatePassword(input.Password); err != nil {
		writeError(w, 422, err.Error())
		return
	}
	var id string
	err := a.Service.DB.QueryRow(r.Context(), `INSERT INTO users(username,display_name,email,role,source,password_hash,must_change_password) VALUES($1,$2,$3,$4,'LOCAL',crypt($5,gen_salt('bf',12)),true) RETURNING id::text`, input.Username, strings.TrimSpace(input.DisplayName), strings.TrimSpace(input.Email), input.Role, input.Password).Scan(&id)
	if err != nil {
		writeError(w, 409, "用户名已存在")
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "username": input.Username, "source": "LOCAL"})
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	current, _ := userFromRequest(r)
	var input struct {
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Role        string `json:"role"`
		Enabled     *bool  `json:"enabled"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || input.Enabled == nil {
		writeError(w, 400, "用户信息格式无效")
		return
	}
	input.Role = strings.ToUpper(strings.TrimSpace(input.Role))
	if input.Role != "ADMIN" && input.Role != "USER" {
		writeError(w, 422, "角色无效")
		return
	}
	if current.ID == r.PathValue("id") && (input.Role != "ADMIN" || !*input.Enabled) {
		writeError(w, 409, "不能停用自己或移除自己的管理员角色")
		return
	}
	if err := a.protectLastAdmin(r.Context(), r.PathValue("id"), input.Role, *input.Enabled); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	tag, err := a.Service.DB.Exec(r.Context(), `UPDATE users SET display_name=$1,email=$2,role=$3,enabled=$4,updated_at=now() WHERE id=$5::uuid`, strings.TrimSpace(input.DisplayName), strings.TrimSpace(input.Email), input.Role, *input.Enabled, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 404, "用户不存在")
		return
	}
	if !*input.Enabled {
		_, _ = a.Service.DB.Exec(r.Context(), `DELETE FROM user_sessions WHERE user_id=$1::uuid`, r.PathValue("id"))
	}
	writeJSON(w, 200, map[string]any{"updated": true})
}

func (a *API) resetLocalUserPassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeError(w, 400, "密码信息格式无效")
		return
	}
	if err := validatePassword(input.Password); err != nil {
		writeError(w, 422, err.Error())
		return
	}
	tag, err := a.Service.DB.Exec(r.Context(), `UPDATE users SET password_hash=crypt($2,gen_salt('bf',12)),must_change_password=true,updated_at=now() WHERE id=$1::uuid AND source='LOCAL'`, r.PathValue("id"), input.Password)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 422, "用户不存在或不是本地用户")
		return
	}
	_, _ = a.Service.DB.Exec(r.Context(), `DELETE FROM user_sessions WHERE user_id=$1::uuid`, r.PathValue("id"))
	writeJSON(w, 200, map[string]any{"updated": true, "must_change_password": true})
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	current, _ := userFromRequest(r)
	if current.ID == r.PathValue("id") {
		writeError(w, 409, "不能删除当前登录账号")
		return
	}
	if err := a.protectLastAdmin(r.Context(), r.PathValue("id"), "USER", false); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	var activeInstances int
	if err := a.Service.DB.QueryRow(r.Context(), `SELECT count(*) FROM instances i JOIN applications ap ON ap.id=i.application_id JOIN users u ON lower(u.username)=lower(ap.applicant) WHERE u.id=$1::uuid`, r.PathValue("id")).Scan(&activeInstances); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if activeInstances > 0 {
		writeError(w, 409, "用户仍有虚拟机，不能删除；可以先停用账号")
		return
	}
	tag, err := a.Service.DB.Exec(r.Context(), `DELETE FROM users WHERE id=$1::uuid`, r.PathValue("id"))
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 404, "用户不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true})
}

func (a *API) protectLastAdmin(ctx context.Context, userID, nextRole string, nextEnabled bool) error {
	var role string
	var enabled bool
	if err := a.Service.DB.QueryRow(ctx, `SELECT role,enabled FROM users WHERE id=$1::uuid`, userID).Scan(&role, &enabled); err != nil {
		return errors.New("用户不存在")
	}
	if role != "ADMIN" || !enabled || nextRole == "ADMIN" && nextEnabled {
		return nil
	}
	var administrators int
	if err := a.Service.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='ADMIN' AND enabled`).Scan(&administrators); err != nil {
		return err
	}
	if administrators <= 1 {
		return errors.New("必须至少保留一个可用管理员")
	}
	return nil
}

func EnsureBootstrapAdmin(ctx context.Context, api *API, username, password string) error {
	if username == "" || password == "" {
		return nil
	}
	if !usernamePattern.MatchString(username) {
		return errors.New("初始化管理员用户名无效")
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	_, err := api.Service.DB.Exec(ctx, `INSERT INTO users(username,display_name,role,source,password_hash,must_change_password) VALUES($1,$1,'ADMIN','LOCAL',crypt($2,gen_salt('bf',12)),true) ON CONFLICT (lower(username)) DO NOTHING`, username, password)
	return err
}
