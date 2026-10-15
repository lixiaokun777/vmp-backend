package background

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type failure struct {
	count     int
	lastAlert time.Time
	err       error
}
type Monitor struct {
	mu      sync.Mutex
	states  map[string]failure
	Now     func() time.Time
	Enqueue func(context.Context, string, int, string) error
}

// ErrorSummary 只输出固定分类，原始错误可能包含 DSN、令牌或 SQL 参数，不能进入群消息。
func ErrorSummary(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "后台操作超过执行时限"
	}
	if errors.Is(err, context.Canceled) {
		return "后台操作被取消"
	}
	return "后台操作失败，请管理员检查服务日志和数据库连接"
}

// Observe 连续三轮失败后告警；恢复时仍尝试补入此前因数据库不可用未能入队的告警。
func (m *Monitor) Observe(ctx context.Context, name string, err error) {
	if ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.states == nil {
		m.states = make(map[string]failure)
	}
	s := m.states[name]
	if err != nil {
		s.count++
		s.err = err
		slog.Error("后台循环执行失败", "loop", name, "consecutive_failures", s.count, "error", err)
	}
	now := time.Now()
	if m.Now != nil {
		now = m.Now()
	}
	if s.count >= 3 && (s.lastAlert.IsZero() || now.Sub(s.lastAlert) >= 30*time.Minute) && m.Enqueue != nil {
		if enqueueErr := m.Enqueue(ctx, name, s.count, ErrorSummary(s.err)); enqueueErr != nil {
			slog.Error("平台健康告警入队失败", "loop", name, "error", enqueueErr)
		} else {
			s.lastAlert = now
		}
	}
	if err == nil {
		s.count = 0
		s.err = nil
	}
	m.states[name] = s
}

func Detail(name string, count int, summary string) string {
	return fmt.Sprintf("循环：%s · 错误摘要：%s · 连续失败：%d 轮", name, summary, count)
}
