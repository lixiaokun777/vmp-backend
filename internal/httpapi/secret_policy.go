package httpapi

import (
	"errors"
	"strings"
	"unicode"
)

// 发布服务必须显式提供随机引导密钥，不能把示例或空配置当成认证身份。
func ValidateAgentBootstrapSecret(value string) error {
	if len(value) < 32 || len(value) > 512 {
		return errors.New("AGENT_BOOTSTRAP_TOKEN 必须为 32 至 512 字节随机值，不允许空值或开发默认值")
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"change", "dev-", "example", "replace", "your-"} {
		if strings.HasPrefix(lower, prefix) {
			return errors.New("AGENT_BOOTSTRAP_TOKEN 不允许使用公开示例值")
		}
	}
	characters := map[rune]bool{}
	for _, char := range value {
		if char > 127 || unicode.IsSpace(char) || unicode.IsControl(char) {
			return errors.New("AGENT_BOOTSTRAP_TOKEN 必须为不含空白的 ASCII 随机值")
		}
		characters[char] = true
	}
	if len(characters) < 8 {
		return errors.New("AGENT_BOOTSTRAP_TOKEN 字符变化不足，请重新生成随机值")
	}
	return nil
}
