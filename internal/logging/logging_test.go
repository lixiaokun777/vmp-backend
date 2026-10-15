package logging

import "testing"

func TestLevels(t *testing.T) {
	for _, v := range []string{"", "debug", "info", "warn", "error"} {
		if err := Init(v); err != nil {
			t.Fatal(err)
		}
	}
	if Init("trace") == nil {
		t.Fatal("非法日志级别被接受")
	}
	_ = Init("info")
}
