package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"vmp-backend/internal/platform"
)

func TestResetPasswordAndRevokeSessionsAtomicDatabase(t *testing.T) {
	db := identityTestDatabase(t)
	ctx := context.Background()
	api := &API{Service: &platform.Service{DB: db}}
	var id string
	if err := db.QueryRow(ctx, `INSERT INTO users(username,source,role,password_hash) VALUES('atomic-reset','LOCAL','USER',crypt('OldStrong123!',gen_salt('bf',4))) RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES(decode(repeat('aa',32),'hex'),$1::uuid,now()+interval '1 hour')`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `CREATE FUNCTION fail_session_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION '模拟会话删除失败'; END $$; CREATE TRIGGER fail_session_delete BEFORE DELETE ON user_sessions FOR EACH ROW EXECUTE FUNCTION fail_session_delete()`); err != nil {
		t.Fatal(err)
	}
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/password", strings.NewReader(`{"password":"NewStrong456!"}`))
		r.SetPathValue("id", id)
		w := httptest.NewRecorder()
		api.resetLocalUserPassword(w, r)
		return w
	}
	if w := request(); w.Code != 500 || strings.Contains(w.Body.String(), "模拟") {
		t.Fatalf("未安全失败 %d %s", w.Code, w.Body.String())
	}
	var oldOK bool
	var sessions int
	if err := db.QueryRow(ctx, `SELECT password_hash=crypt('OldStrong123!',password_hash),(SELECT count(*) FROM user_sessions WHERE user_id=$1::uuid) FROM users WHERE id=$1::uuid`, id).Scan(&oldOK, &sessions); err != nil || !oldOK || sessions != 1 {
		t.Fatalf("密码或会话未回滚 old=%v sessions=%d err=%v", oldOK, sessions, err)
	}
	if _, err := db.Exec(ctx, `DROP TRIGGER fail_session_delete ON user_sessions`); err != nil {
		t.Fatal(err)
	}
	if w := request(); w.Code != 200 {
		t.Fatalf("重置失败 %d %s", w.Code, w.Body.String())
	}
	if err := db.QueryRow(ctx, `SELECT password_hash=crypt('NewStrong456!',password_hash),(SELECT count(*) FROM user_sessions WHERE user_id=$1::uuid) FROM users WHERE id=$1::uuid`, id).Scan(&oldOK, &sessions); err != nil || !oldOK || sessions != 0 {
		t.Fatalf("密码或会话未提交 err=%v", err)
	}
}
