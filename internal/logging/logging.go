package logging

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Init 在启动业务线程前统一设置日志级别，非法配置直接拒绝启动。
func Init(value string) error {
	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("LOG_LEVEL 必须为 debug/info/warn/error")
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	return nil
}
