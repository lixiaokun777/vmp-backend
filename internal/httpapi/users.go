package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{2,64}$`)

func (a *API) users(w http.ResponseWriter, r *http.Request) {
	a.usersPage(w, r)
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
	current, _ := userFromRequest(r)
	tx, err := a.beginUserAdministration(r.Context(), current.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	var id string
	err = tx.QueryRow(r.Context(), `INSERT INTO users(username,display_name,email,role,source,password_hash,must_change_password) VALUES($1,$2,$3,$4,'LOCAL',crypt($5,gen_salt('bf',12)),true) RETURNING id::text`, input.Username, strings.TrimSpace(input.DisplayName), strings.TrimSpace(input.Email), input.Role, input.Password).Scan(&id)
	if err != nil {
		writeError(w, 409, "用户名已存在")
		return
	}
	if err := requireLocalAdministrator(r.Context(), tx); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, 500, "创建用户未完成，请重试")
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
	tx, err := a.beginUserAdministration(r.Context(), current.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), `UPDATE users SET display_name=$1,email=$2,role=$3,enabled=$4,updated_at=now() WHERE id=$5::uuid`, strings.TrimSpace(input.DisplayName), strings.TrimSpace(input.Email), input.Role, *input.Enabled, r.PathValue("id"))
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 404, "用户不存在")
		return
	}
	if err := requireLocalAdministrator(r.Context(), tx); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if !*input.Enabled {
		if _, err := tx.Exec(r.Context(), `DELETE FROM user_sessions WHERE user_id=$1::uuid`, r.PathValue("id")); err != nil {
			writeError(w, 500, "清理用户会话失败")
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, 500, "更新用户未完成，请重试")
		return
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
	tx, err := a.beginUserAdministration(r.Context(), current.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	var username string
	if err := tx.QueryRow(r.Context(), `SELECT username FROM users WHERE id=$1::uuid`, r.PathValue("id")).Scan(&username); err != nil {
		writeError(w, 404, "用户不存在")
		return
	}
	if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended('user-quota:'||lower($1),0))`, username); err != nil {
		writeError(w, 500, "无法锁定用户资源")
		return
	}
	if err := tx.QueryRow(r.Context(), `SELECT username FROM users WHERE id=$1::uuid FOR UPDATE`, r.PathValue("id")).Scan(&username); err != nil {
		writeError(w, 404, "用户已删除或发生变化")
		return
	}
	var activeInstances int
	if err := tx.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM instances i JOIN applications ap ON ap.id=i.application_id WHERE lower(ap.applicant)=lower($1))+(SELECT count(*) FROM approval_requests WHERE lower(applicant)=lower($1) AND status IN ('PENDING','PROCESSING'))`, username).Scan(&activeInstances); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if activeInstances > 0 {
		writeError(w, 409, "用户仍有虚拟机或待处理审批，不能删除；可以先停用账号")
		return
	}
	tag, err := tx.Exec(r.Context(), `DELETE FROM users WHERE id=$1::uuid`, r.PathValue("id"))
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if err := requireLocalAdministrator(r.Context(), tx); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, 500, "删除用户未完成，请重试")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 404, "用户不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true})
}

const userAdministrationLock int64 = 73124509167

// 全局事务锁覆盖操作者复核、变更和最后本地管理员计数，不能只读后另行写入。
func (a *API) beginUserAdministration(ctx context.Context, operatorID string) (pgx.Tx, error) {
	tx, err := a.Service.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, userAdministrationLock); err != nil {
		tx.Rollback(ctx)
		return nil, err
	}
	var valid bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid AND role='ADMIN' AND enabled AND NOT must_change_password AND (source<>'LDAP' OR ldap_directory_present))`, operatorID).Scan(&valid)
	if err != nil || !valid {
		tx.Rollback(ctx)
		return nil, errors.New("管理员身份已失效，请重新登录")
	}
	return tx, nil
}
func requireLocalAdministrator(ctx context.Context, tx pgx.Tx) error {
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='ADMIN' AND enabled AND source='LOCAL'`).Scan(&count); err != nil {
		return err
	}
	if count < 1 {
		return errors.New("必须至少保留一个启用的本地应急管理员；LDAP不能代替本地应急账号")
	}
	return nil
}

func EnsureBootstrapAdmin(ctx context.Context, api *API, username, password string) error {
	var existingLocal int
	if err := api.Service.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='ADMIN' AND enabled AND source='LOCAL'`).Scan(&existingLocal); err != nil {
		return err
	}
	if existingLocal > 0 {
		return nil
	}
	if username == "" || password == "" {
		return errors.New("缺少本地应急管理员，请设置新的BOOTSTRAP_ADMIN_USERNAME和强密码初始化，已有账号不会自动提升")
	}
	if !usernamePattern.MatchString(username) {
		return errors.New("初始化管理员用户名无效")
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	_, err := api.Service.DB.Exec(ctx, `INSERT INTO users(username,display_name,role,source,password_hash,must_change_password) VALUES($1,$1,'ADMIN','LOCAL',crypt($2,gen_salt('bf',12)),true) ON CONFLICT (lower(username)) DO NOTHING`, username, password)
	if err != nil {
		return err
	}
	if err := api.Service.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='ADMIN' AND enabled AND source='LOCAL'`).Scan(&existingLocal); err != nil {
		return err
	}
	if existingLocal == 0 {
		return errors.New("初始化本地应急管理员用户名已被占用，请选择未使用的新名称，禁止自动改写旧账号")
	}
	return nil
}
