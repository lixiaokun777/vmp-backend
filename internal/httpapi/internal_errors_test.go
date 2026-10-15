package httpapi

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInternalErrorsNeverExposeOriginalMessage(t *testing.T) {
	w := httptest.NewRecorder()
	internalError(w, httptest.NewRequest("GET", "/api/v1/users", nil), errors.New("SQL password=private DSN=postgres://private"))
	if w.Code != 500 || !strings.Contains(w.Body.String(), "服务器内部错误，请稍后重试") || strings.Contains(w.Body.String(), "private") {
		t.Fatal("内部错误泄漏")
	}
	w = httptest.NewRecorder()
	writeError(w, 422, "实例名称不合法")
	if !strings.Contains(w.Body.String(), "实例名称不合法") {
		t.Fatal("校验文案被替换")
	}
}
