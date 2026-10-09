package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// 子进程验证真正启动入口在连接数据库之前拒绝不安全凭据，不访问外部服务。
func TestStartupRejectsMissingAgentBootstrap(t *testing.T) {
	if os.Getenv("VMP_TEST_STARTUP_POLICY_CHILD") == "1" {
		main()
		return
	}
	for _, value := range []string{"", "dev-bootstrap-token", "change-bootstrap-token", strings.Repeat("x", 64)} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStartupRejectsMissingAgentBootstrap$")
		for _, item := range os.Environ() {
			if !strings.HasPrefix(item, "AGENT_BOOTSTRAP_TOKEN=") && !strings.HasPrefix(item, "DATABASE_URL=") {
				cmd.Env = append(cmd.Env, item)
			}
		}
		cmd.Env = append(cmd.Env, "VMP_TEST_STARTUP_POLICY_CHILD=1", "AGENT_BOOTSTRAP_TOKEN="+value, "DATABASE_URL=not-a-valid-connection-string")
		output, err := cmd.CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("拒绝启动")) || bytes.Contains(output, []byte("database connection failed")) {
			t.Fatal("启动入口没有在数据库连接前拒绝弱或空引导凭据")
		}
	}
}
