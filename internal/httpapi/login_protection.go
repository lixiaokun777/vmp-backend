package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// 只信任明确配置的代理；公网客户端不能通过伪造转发头更换限流身份。
func ParseTrustedProxies(value string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("可信代理必须是 CIDR：%q", item)
		}
		if prefix.Bits() == 0 {
			return nil, errors.New("可信代理不能配置为全部网络")
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func (a *API) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	peer = peer.Unmap()
	trusted := func(ip netip.Addr) bool {
		for _, prefix := range a.TrustedProxies {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !trusted(peer) {
		return peer.String()
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	// 从直连代理向左剥离可信节点，遇到第一个非可信节点即停止。
	if len(chain) > 16 {
		return peer.String()
	}
	for i := len(chain) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil {
			return peer.String()
		}
		ip = ip.Unmap()
		if !trusted(ip) {
			return ip.String()
		}
		peer = ip
	}
	return peer.String()
}

func loginBucketKey(kind, value string) string {
	sum := sha256.Sum256([]byte(value))
	return kind + ":" + hex.EncodeToString(sum[:])
}

type loginReservation struct {
	Key       string
	Attempts  int
	ExpiresAt time.Time
}

// 密码校验前预占一次尝试，避免并发请求全部越过失败计数。
// 达到上限后不延长窗口，防止攻击者无限续锁；未知账号与已存在账号走相同流程。
func (a *API) reserveLogin(ctx context.Context, key string, limit int, window time.Duration) (loginReservation, time.Duration, error) {
	token := loginReservation{Key: key}
	err := a.Service.DB.QueryRow(ctx, `INSERT INTO login_attempt_buckets(bucket_key,attempts,expires_at)
 VALUES($1,1,clock_timestamp()+$3*interval '1 second')
 ON CONFLICT(bucket_key) DO UPDATE SET
 attempts=CASE WHEN login_attempt_buckets.expires_at<=clock_timestamp() THEN 1 ELSE login_attempt_buckets.attempts+1 END,
 expires_at=CASE WHEN login_attempt_buckets.expires_at<=clock_timestamp() THEN clock_timestamp()+$3*interval '1 second' ELSE login_attempt_buckets.expires_at END
 WHERE login_attempt_buckets.expires_at<=clock_timestamp() OR login_attempt_buckets.attempts<$2
 RETURNING attempts,expires_at`, key, limit, int(window.Seconds())).Scan(&token.Attempts, &token.ExpiresAt)
	if err == nil {
		return token, 0, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return token, 0, err
	}
	var seconds float64
	err = a.Service.DB.QueryRow(ctx, `SELECT greatest(1,extract(epoch FROM expires_at-clock_timestamp())) FROM login_attempt_buckets WHERE bucket_key=$1`, key).Scan(&seconds)
	if errors.Is(err, pgx.ErrNoRows) {
		return token, time.Second, nil
	}
	return token, time.Duration(math.Ceil(seconds)) * time.Second, err
}

func (a *API) allowLogin(w http.ResponseWriter, r *http.Request, key string, limit int, window time.Duration) (loginReservation, bool) {
	token, retry, err := a.reserveLogin(r.Context(), key, limit, window)
	if err != nil {
		// 保护存储故障时关闭登录，不悄悄降级为无限密码校验。
		writeError(w, 503, "登录保护暂不可用，请稍后重试")
		return token, false
	}
	if retry > 0 {
		seconds := int(retry.Seconds())
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		writeError(w, 429, fmt.Sprintf("登录尝试过于频繁，请在 %d 秒后重试", seconds))
		return token, false
	}
	return token, true
}

func (a *API) resetLoginReservation(ctx context.Context, token loginReservation) {
	// 有并发失败时保留新计数，成功请求不能抹掉随后产生的失败。
	_, _ = a.Service.DB.Exec(ctx, `DELETE FROM login_attempt_buckets WHERE bucket_key=$1 AND attempts=$2 AND expires_at=$3`, token.Key, token.Attempts, token.ExpiresAt)
}

func (a *API) StartLoginProtectionCleanup(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, _ = a.Service.DB.Exec(cleanupCtx, `DELETE FROM login_attempt_buckets WHERE bucket_key IN (SELECT bucket_key FROM login_attempt_buckets WHERE expires_at<now()-interval '1 day' ORDER BY expires_at LIMIT 5000)`)
			cancel()
		}
	}
}
