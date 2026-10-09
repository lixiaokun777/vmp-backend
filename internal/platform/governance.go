package platform

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type GovernancePolicy struct {
	MaxInstances              int  `json:"max_instances"`
	MaxCPU                    int  `json:"max_cpu"`
	MaxMemoryMB               int  `json:"max_memory_mb"`
	MaxDiskGB                 int  `json:"max_disk_gb"`
	MaxFutureLeaseHours       int  `json:"max_future_lease_hours"`
	MaxContinuousLeaseHours   int  `json:"max_continuous_lease_hours"`
	AutoRenewEnabled          bool `json:"auto_renew_enabled"`
	AutoRenewMaxCount         int  `json:"auto_renew_max_count"`
	AutoRenewHours            int  `json:"auto_renew_hours"`
	AuditRetentionDays        int  `json:"audit_retention_days"`
	NotificationRetentionDays int  `json:"notification_retention_days"`
	ApprovalRetentionDays     int  `json:"approval_retention_days"`
}

type policyQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readPolicy(ctx context.Context, db policyQuerier, lock bool) (GovernancePolicy, error) {
	var p GovernancePolicy
	sql := `SELECT max_instances,max_cpu,max_memory_mb,max_disk_gb,max_future_lease_hours,max_continuous_lease_hours,auto_renew_enabled,auto_renew_max_count,auto_renew_hours,audit_retention_days,notification_retention_days,approval_retention_days FROM platform_policy WHERE singleton`
	if lock {
		sql += ` FOR SHARE`
	}
	err := db.QueryRow(ctx, sql).Scan(&p.MaxInstances, &p.MaxCPU, &p.MaxMemoryMB, &p.MaxDiskGB, &p.MaxFutureLeaseHours, &p.MaxContinuousLeaseHours, &p.AutoRenewEnabled, &p.AutoRenewMaxCount, &p.AutoRenewHours, &p.AuditRetentionDays, &p.NotificationRetentionDays, &p.ApprovalRetentionDays)
	return p, err
}

func (s *Service) GetPolicy(ctx context.Context) (GovernancePolicy, error) {
	return readPolicy(ctx, s.DB, false)
}

// 归档清理和资源写入共用策略行锁，保存新策略不能穿过已开始的检查事务。
func (s *Service) GetPolicyTx(ctx context.Context, tx pgx.Tx) (GovernancePolicy, error) {
	return readPolicy(ctx, tx, true)
}

func (p GovernancePolicy) Validate() error {
	for _, n := range []int{p.MaxInstances, p.MaxCPU, p.MaxMemoryMB, p.MaxDiskGB, p.MaxFutureLeaseHours, p.MaxContinuousLeaseHours} {
		if n < 0 || n > 100000000 {
			return errors.New("额度必须为 0 至 100000000，0 表示不限制")
		}
	}
	if p.MaxFutureLeaseHours > 876000 || p.MaxContinuousLeaseHours > 876000 {
		return errors.New("未来或连续租期上限不能超过 876000 小时（100 年）")
	}
	if p.AutoRenewHours < 1 || p.AutoRenewHours > 168 || p.AutoRenewMaxCount < 1 || p.AutoRenewMaxCount > 100 {
		return errors.New("自动续期每次必须为 1-168 小时，次数上限为 1-100")
	}
	if p.AuditRetentionDays != 0 && p.AuditRetentionDays < 180 || p.NotificationRetentionDays != 0 && p.NotificationRetentionDays < 30 || p.ApprovalRetentionDays != 0 && p.ApprovalRetentionDays < 90 {
		return errors.New("历史可永久保留（0）；审计至少 180 天、通知至少 30 天、审批至少 90 天")
	}
	for _, n := range []int{p.AuditRetentionDays, p.NotificationRetentionDays, p.ApprovalRetentionDays} {
		if n > 36500 {
			return errors.New("历史期限不能超过 36500 天")
		}
	}
	return nil
}

func (s *Service) SavePolicy(ctx context.Context, actor string, p GovernancePolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	_, err := s.DB.Exec(ctx, `UPDATE platform_policy SET max_instances=$1,max_cpu=$2,max_memory_mb=$3,max_disk_gb=$4,max_future_lease_hours=$5,max_continuous_lease_hours=$6,auto_renew_enabled=$7,auto_renew_max_count=$8,auto_renew_hours=$9,audit_retention_days=$10,notification_retention_days=$11,approval_retention_days=$12,updated_by=$13,updated_at=now() WHERE singleton`, p.MaxInstances, p.MaxCPU, p.MaxMemoryMB, p.MaxDiskGB, p.MaxFutureLeaseHours, p.MaxContinuousLeaseHours, p.AutoRenewEnabled, p.AutoRenewMaxCount, p.AutoRenewHours, p.AuditRetentionDays, p.NotificationRetentionDays, p.ApprovalRetentionDays, actor)
	return err
}

// 用户级事务锁覆盖检查和预占，两个并发申请不能同时通过同一额度。
func (s *Service) enforceCreateQuota(ctx context.Context, tx pgx.Tx, actor string, cpu, memory, disk, hours int) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('user-quota:'||lower($1),0))`, actor); err != nil {
		return err
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT enabled AND (source<>'LDAP' OR ldap_directory_present) FROM users WHERE lower(username)=lower($1) FOR SHARE`, actor).Scan(&active); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("申请账号不存在、已停用或目录授权失效")
		}
		return err
	}
	if !active {
		return errors.New("申请账号不存在、已停用或目录授权失效")
	}
	p, err := readPolicy(ctx, tx, true)
	if err != nil {
		return err
	}
	var count, usedCPU, usedMemory, usedDisk int
	if err = tx.QueryRow(ctx, `SELECT count(*),coalesce(sum(i.allocated_cpu),0),coalesce(sum(i.allocated_memory_mb),0),coalesce(sum(i.allocated_disk_gb),0) FROM instances i JOIN applications a ON a.id=i.application_id WHERE lower(a.applicant)=lower($1) AND i.lifecycle_status<>'RELEASED'`, actor).Scan(&count, &usedCPU, &usedMemory, &usedDisk); err != nil {
		return err
	}
	for _, item := range []struct {
		name             string
		used, add, limit int
	}{{"实例数量", count, 1, p.MaxInstances}, {"CPU", usedCPU, cpu, p.MaxCPU}, {"内存 MiB", usedMemory, memory, p.MaxMemoryMB}, {"磁盘 GiB", usedDisk, disk, p.MaxDiskGB}} {
		if item.limit > 0 && item.used+item.add > item.limit {
			return fmt.Errorf("用户%s额度不足：已用 %d，本次 %d，上限 %d（保留期和失败待清理实例仍占额度）", item.name, item.used, item.add, item.limit)
		}
	}
	if p.MaxFutureLeaseHours > 0 && hours > p.MaxFutureLeaseHours || p.MaxContinuousLeaseHours > 0 && hours > p.MaxContinuousLeaseHours {
		return errors.New("申请租期超过平台配置的未来租期或连续租期上限")
	}
	return nil
}

func (s *Service) enforceLeasePolicy(ctx context.Context, tx pgx.Tx, owner, instanceID string, nextExpiry time.Time) error {
	p, err := readPolicy(ctx, tx, true)
	if err != nil {
		return err
	}
	var created time.Time
	if err = tx.QueryRow(ctx, `SELECT created_at FROM instances WHERE id=$1::uuid`, instanceID).Scan(&created); err != nil {
		return err
	}
	now := time.Now()
	if p.MaxFutureLeaseHours > 0 && nextExpiry.After(now.Add(time.Duration(p.MaxFutureLeaseHours)*time.Hour+time.Second)) {
		return errors.New("续期后的剩余租期超过平台上限")
	}
	if p.MaxContinuousLeaseHours > 0 && nextExpiry.After(created.Add(time.Duration(p.MaxContinuousLeaseHours)*time.Hour)) {
		return errors.New("续期后的连续占用期限超过平台上限，请备份并释放资源")
	}
	return nil
}

// 分配是通知路由而非新的越权入口；任何有效管理员仍可应急审批，所有转交都会留痕。
func assignApproval(ctx context.Context, db policyQuerier) (string, string, error) {
	var owner, reviewer string
	err := db.QueryRow(ctx, `SELECT u.username,coalesce(d.delegate_username,u.username) FROM users u LEFT JOIN approval_delegations d ON d.owner_username=u.username AND d.starts_at<=now() AND d.ends_at>now() AND EXISTS(SELECT 1 FROM users du WHERE du.username=d.delegate_username AND du.role='ADMIN' AND du.enabled AND (du.source<>'LDAP' OR du.ldap_directory_present)) WHERE u.role='ADMIN' AND u.enabled AND (u.source<>'LDAP' OR u.ldap_directory_present) ORDER BY (SELECT count(*) FROM approval_requests ar WHERE ar.status='PENDING' AND ar.assigned_reviewer=coalesce(d.delegate_username,u.username)),u.created_at,u.username LIMIT 1`).Scan(&owner, &reviewer)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	if owner == reviewer {
		owner = ""
	}
	return reviewer, owner, nil
}

func (s *Service) RefreshDelegations(ctx context.Context) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(8673230)`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE approval_requests ar SET assigned_reviewer=coalesce((SELECT d.delegate_username FROM approval_delegations d JOIN users u ON u.username=d.delegate_username WHERE d.owner_username=coalesce(ar.delegated_from,ar.assigned_reviewer) AND d.starts_at<=now() AND d.ends_at>now() AND u.role='ADMIN' AND u.enabled AND (u.source<>'LDAP' OR u.ldap_directory_present)),coalesce(ar.delegated_from,ar.assigned_reviewer)),delegated_from=CASE WHEN EXISTS(SELECT 1 FROM approval_delegations d JOIN users u ON u.username=d.delegate_username WHERE d.owner_username=coalesce(ar.delegated_from,ar.assigned_reviewer) AND d.starts_at<=now() AND d.ends_at>now() AND u.role='ADMIN' AND u.enabled AND (u.source<>'LDAP' OR u.ldap_directory_present)) THEN coalesce(ar.delegated_from,ar.assigned_reviewer) ELSE NULL END WHERE ar.status='PENDING' AND ar.assigned_reviewer IS NOT NULL`); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT ar.id::text FROM approval_requests ar WHERE ar.status='PENDING' AND ar.expires_at>now() AND NOT EXISTS(SELECT 1 FROM users u WHERE u.username=ar.assigned_reviewer AND u.role='ADMIN' AND u.enabled AND (u.source<>'LDAP' OR u.ldap_directory_present)) ORDER BY ar.created_at LIMIT 500 FOR UPDATE`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// 原审批人停用/删除后有限批次重分配，不把过期或已处理单据拉回待办。
	for _, id := range ids {
		reviewer, from, assignErr := assignApproval(ctx, tx)
		if assignErr != nil {
			return assignErr
		}
		if _, err = tx.Exec(ctx, `UPDATE approval_requests SET assigned_reviewer=nullif($2,''),delegated_from=nullif($3,''),updated_at=now() WHERE id=$1::uuid`, id, reviewer, from); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) RunAutoRenew(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `SELECT ar.instance_id::text FROM instance_auto_renew ar JOIN instances i ON i.id=ar.instance_id WHERE ar.enabled AND i.lifecycle_status IN ('RUNNING','STOPPED') AND i.expires_at>now() AND i.expires_at<=now()+interval '1 hour' ORDER BY i.expires_at LIMIT 100`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = s.autoRenewOne(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) autoRenewOne(ctx context.Context, id string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var owner, status string
	var expiry time.Time
	if err = tx.QueryRow(ctx, `SELECT a.applicant,i.lifecycle_status,i.expires_at FROM instances i JOIN applications a ON a.id=i.application_id WHERE i.id=$1::uuid FOR UPDATE OF i SKIP LOCKED`, id).Scan(&owner, &status, &expiry); errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	p, err := readPolicy(ctx, tx, true)
	if err != nil {
		return err
	}
	var enabled bool
	var hours, maxCount, count int
	if err = tx.QueryRow(ctx, `SELECT enabled,hours,max_renewals,renewed_count FROM instance_auto_renew WHERE instance_id=$1::uuid FOR UPDATE`, id).Scan(&enabled, &hours, &maxCount, &count); err != nil {
		return err
	}
	if !enabled || expiry.Before(time.Now()) || expiry.After(time.Now().Add(time.Hour)) || (status != "RUNNING" && status != "STOPPED") {
		return nil
	}
	var ownerActive bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1 AND enabled AND (source<>'LDAP' OR ldap_directory_present))`, owner).Scan(&ownerActive); err != nil {
		return err
	}
	failure := ""
	if !p.AutoRenewEnabled {
		failure = "管理员已关闭自动续期"
	} else if !ownerActive {
		failure = "账号已停用或目录授权失效"
	} else if count >= min(maxCount, p.AutoRenewMaxCount) {
		failure = "已达到自动续期次数上限"
	} else if hours > p.AutoRenewHours {
		failure = "自动续期小时超过平台上限"
	} else if policyErr := s.enforceLeasePolicy(ctx, tx, owner, id, expiry.Add(time.Duration(hours)*time.Hour)); policyErr != nil {
		failure = policyErr.Error()
	}
	if failure != "" {
		_, err = tx.Exec(ctx, `UPDATE instance_auto_renew SET enabled=false,last_error=$2,updated_at=now() WHERE instance_id=$1::uuid`, id, failure)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,outcome,detail) VALUES('system:auto-renew','instance.auto_renew','instance',$1,'FAILED',jsonb_build_object('error',$2::text))`, id, failure)
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if _, err = s.renewInstanceTx(ctx, tx, owner, false, id, hours, "用户已授权的自动续期"); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE instance_auto_renew SET renewed_count=renewed_count+1,last_error='',updated_at=now() WHERE instance_id=$1::uuid`, id)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// 自动续期策略修改不会重置已用次数，避免反复开关绕过上限。
func (s *Service) SetAutoRenew(ctx context.Context, actor string, admin bool, id string, enabled bool, hours, maxCount int) error {
	if !uuidPattern.MatchString(id) || hours < 1 || hours > 168 || maxCount < 1 || maxCount > 100 {
		return errors.New("自动续期配置无效")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var owner, status string
	if err = tx.QueryRow(ctx, `SELECT a.applicant,i.lifecycle_status FROM instances i JOIN applications a ON a.id=i.application_id WHERE i.id=$1::uuid FOR UPDATE OF i`, id).Scan(&owner, &status); err != nil {
		return err
	}
	if owner != actor && !admin {
		return errors.New("实例不属于当前用户")
	}
	p, err := readPolicy(ctx, tx, true)
	if err != nil {
		return err
	}
	if enabled && (!p.AutoRenewEnabled || hours > p.AutoRenewHours || maxCount > p.AutoRenewMaxCount || status != "RUNNING" && status != "STOPPED") {
		return errors.New("平台未开启自动续期、超出上限，或实例状态不可续期")
	}
	_, err = tx.Exec(ctx, `INSERT INTO instance_auto_renew(instance_id,enabled,hours,max_renewals) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(instance_id) DO UPDATE SET enabled=excluded.enabled,hours=excluded.hours,max_renewals=excluded.max_renewals,last_error='',updated_at=now()`, id, enabled, hours, maxCount)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'instance.auto_renew.configure','instance',$2,jsonb_build_object('enabled',$3::boolean,'hours',$4::integer,'max_renewals',$5::integer))`, strings.TrimSpace(actor), id, enabled, hours, maxCount)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
