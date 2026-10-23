package platform

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	ScheduleMostAvailable = "MOST_AVAILABLE"
	ScheduleRoundRobin    = "ROUND_ROBIN"
	ScheduleBalanced      = "BALANCED"
)

var ErrSchedulingInput = errors.New("调度预览参数无效")

func invalidSchedulingInput(message string) error {
	return fmt.Errorf("%w：%s", ErrSchedulingInput, message)
}

func validSchedulingStrategy(strategy string) bool {
	return strategy == ScheduleMostAvailable || strategy == ScheduleRoundRobin || strategy == ScheduleBalanced
}

type SchedulingRequest struct {
	FlavorID  string `json:"flavor_id"`
	ImageID   string `json:"image_id"`
	NetworkID string `json:"network_id"`
	Strategy  string `json:"strategy"`
}

type schedulerPosition struct {
	Sequence    int64      `json:"sequence"`
	HostID      string     `json:"last_host_id"`
	HostName    string     `json:"last_host_name"`
	CreatedAt   time.Time  `json:"-"`
	ScheduledAt *time.Time `json:"last_scheduled_at"`
}

type schedulingResources struct {
	CPU      int `json:"cpu"`
	MemoryMB int `json:"memory_mb"`
	DiskGB   int `json:"disk_gb"`
}

type schedulingCandidate struct {
	ID              string    `json:"host_id"`
	Name            string    `json:"host_name"`
	Eligible        bool      `json:"eligible"`
	Reasons         []string  `json:"reasons"`
	ProjectedCPU    float64   `json:"projected_cpu_ratio"`
	ProjectedMemory float64   `json:"projected_memory_ratio"`
	ProjectedDisk   float64   `json:"projected_disk_ratio"`
	Score           float64   `json:"dominant_ratio"`
	RemainingMemory int       `json:"remaining_memory_mb"`
	LastSequence    int64     `json:"last_scheduled_sequence"`
	CreatedAt       time.Time `json:"-"`
}

type SchedulingDecision struct {
	Strategy        string    `json:"strategy"`
	HostID          string    `json:"host_id"`
	HostName        string    `json:"host_name"`
	Reason          string    `json:"reason"`
	Sequence        int64     `json:"sequence"`
	SelectedAt      time.Time `json:"selected_at"`
	ProjectedCPU    float64   `json:"projected_cpu_ratio"`
	ProjectedMemory float64   `json:"projected_memory_ratio"`
	ProjectedDisk   float64   `json:"projected_disk_ratio"`
	EligibleHosts   int       `json:"eligible_hosts"`
}

// 所有策略和只读预览共用候选条件；实时余量扣除尚未被宿主采样覆盖的预占资源。
const schedulingCandidatesSQL = `SELECT h.id::text,h.name,h.created_at,h.last_scheduled_sequence,
 h.status='ACTIVE',h.agent_mode='kvm',h.budget_source='CONFIGURED_TOTAL',
 coalesce(h.last_heartbeat_at BETWEEN now()-interval '120 seconds' AND now()+interval '30 seconds',false),
 coalesce(h.resource_measured_at BETWEEN now()-interval '120 seconds' AND now()+interval '30 seconds',false),
 h.allocatable_cpu,h.allocatable_memory_mb,h.allocatable_disk_gb,h.reserved_cpu,h.reserved_memory_mb,h.reserved_disk_gb,
 coalesce(h.safe_available_memory_mb,0)-coalesce((SELECT sum(p.allocated_memory_mb) FROM instances p WHERE p.host_id=h.id AND p.lifecycle_status<>'RELEASED' AND (p.created_at>h.resource_measured_at OR p.lifecycle_status IN ('PROVISIONING','STARTING') AND NOT(coalesce(p.last_domain_seen_at>=h.resource_measured_at AND p.observed_domain_status='RUNNING',false)))),0),
 coalesce(h.safe_available_disk_gb,0)-coalesce((SELECT sum(p.allocated_disk_gb) FROM instances p WHERE p.host_id=h.id AND p.lifecycle_status<>'RELEASED' AND (p.created_at>h.resource_measured_at OR p.lifecycle_status='PROVISIONING' AND NOT(coalesce(p.last_domain_seen_at>=h.resource_measured_at,false)))),0),
 EXISTS(SELECT 1 FROM host_images hi WHERE hi.host_id=h.id AND hi.image_id=$4 AND hi.generation=$5 AND hi.status='READY' AND hi.reported_at BETWEEN now()-interval '120 seconds' AND now()+interval '30 seconds'),
 EXISTS(SELECT 1 FROM host_networks hn JOIN networks n ON n.id=hn.network_id AND n.enabled AND n.bridge=hn.bridge WHERE hn.host_id=h.id AND hn.network_id=$6::uuid AND hn.ready AND hn.reported_at BETWEEN now()-interval '120 seconds' AND now()+interval '30 seconds'),
 $1::integer,$2::integer,$3::integer FROM hosts h`

func schedulingArgs(resources schedulingResources, image string, generation int, network string) []any {
	return []any{resources.CPU, resources.MemoryMB, resources.DiskGB, image, generation, network}
}

func scanSchedulingCandidate(row interface{ Scan(...any) error }) (schedulingCandidate, error) {
	var c schedulingCandidate
	var active, writable, budget, heartbeat, measured, image, network bool
	var total, reserved, request schedulingResources
	var safeMemory, safeDisk int64
	err := row.Scan(&c.ID, &c.Name, &c.CreatedAt, &c.LastSequence, &active, &writable, &budget, &heartbeat, &measured,
		&total.CPU, &total.MemoryMB, &total.DiskGB, &reserved.CPU, &reserved.MemoryMB, &reserved.DiskGB, &safeMemory, &safeDisk, &image, &network,
		&request.CPU, &request.MemoryMB, &request.DiskGB)
	if err != nil {
		return c, err
	}
	c.Reasons = []string{}
	for _, check := range []struct {
		ok     bool
		reason string
	}{
		{active, "宿主未启用调度"}, {writable, "Agent 不是 KVM 可写模式"}, {budget, "资源预算尚未就绪"},
		{heartbeat, "宿主心跳过期"}, {measured, "实时资源采样过期"},
		{total.CPU-reserved.CPU >= request.CPU, "CPU 平台额度不足"},
		{total.MemoryMB-reserved.MemoryMB >= request.MemoryMB, "内存平台额度不足"},
		{total.DiskGB-reserved.DiskGB >= request.DiskGB, "磁盘平台额度不足"},
		{safeMemory >= int64(request.MemoryMB), "实时内存安全余量不足"}, {safeDisk >= int64(request.DiskGB), "实时磁盘安全余量不足"},
		{image, "目标镜像未就绪或校验已过期"}, {network, "目标网络或网桥未就绪"},
	} {
		if !check.ok {
			c.Reasons = append(c.Reasons, check.reason)
		}
	}
	c.Eligible = len(c.Reasons) == 0
	c.RemainingMemory = total.MemoryMB - reserved.MemoryMB
	// 未配置额度的宿主仍显示为不可调度；有限比值保证 JSON 不出现 NaN/Inf。
	c.ProjectedCPU = float64(reserved.CPU+request.CPU) / float64(max(1, total.CPU))
	c.ProjectedMemory = float64(reserved.MemoryMB+request.MemoryMB) / float64(max(1, total.MemoryMB))
	c.ProjectedDisk = float64(reserved.DiskGB+request.DiskGB) / float64(max(1, total.DiskGB))
	c.Score = math.Max(c.ProjectedCPU, math.Max(c.ProjectedMemory, c.ProjectedDisk))
	return c, nil
}

func loadSchedulingCandidates(ctx context.Context, tx pgx.Tx, args []any) ([]schedulingCandidate, error) {
	rows, err := tx.Query(ctx, schedulingCandidatesSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []schedulingCandidate{}
	for rows.Next() {
		c, err := scanSchedulingCandidate(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return items, rows.Err()
}

func schedulingOrderLess(created time.Time, id string, otherCreated time.Time, otherID string) bool {
	if !created.Equal(otherCreated) {
		return created.Before(otherCreated)
	}
	return id < otherID
}

func rankSchedulingCandidates(items []schedulingCandidate, strategy string, position schedulerPosition) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Eligible != b.Eligible {
			return a.Eligible
		}
		if strategy == ScheduleRoundRobin {
			afterA := schedulingOrderLess(position.CreatedAt, position.HostID, a.CreatedAt, a.ID)
			afterB := schedulingOrderLess(position.CreatedAt, position.HostID, b.CreatedAt, b.ID)
			if afterA != afterB {
				return afterA
			}
			return schedulingOrderLess(a.CreatedAt, a.ID, b.CreatedAt, b.ID)
		}
		if strategy == ScheduleBalanced {
			if a.Score != b.Score {
				return a.Score < b.Score
			}
		} else if a.RemainingMemory != b.RemainingMemory {
			return a.RemainingMemory > b.RemainingMemory
		}
		if a.LastSequence != b.LastSequence {
			return a.LastSequence < b.LastSequence
		}
		return schedulingOrderLess(a.CreatedAt, a.ID, b.CreatedAt, b.ID)
	})
}

func readSchedulerPosition(ctx context.Context, db policyQuerier, lock bool) (schedulerPosition, error) {
	var p schedulerPosition
	query := `SELECT sequence,last_host_id,last_host_name,last_host_created_at,last_scheduled_at FROM scheduler_state WHERE singleton`
	if lock {
		query += ` FOR UPDATE`
	}
	err := db.QueryRow(ctx, query).Scan(&p.Sequence, &p.HostID, &p.HostName, &p.CreatedAt, &p.ScheduledAt)
	return p, err
}

func schedulingReason(strategy string, c schedulingCandidate) string {
	switch strategy {
	case ScheduleRoundRobin:
		return "按宿主纳管顺序轮询，跳过不满足条件的宿主"
	case ScheduleBalanced:
		return fmt.Sprintf("分配后 CPU / 内存 / 磁盘最高预算占用率 %.1f%% 最低；同分优先更久未接单的宿主", c.Score*100)
	default:
		return "剩余可分配内存优先；相同余量优先更久未接单的宿主"
	}
}

// 调度状态行串行化选择；实际宿主再加行锁复核，进度、预占和任务随外层事务一起提交或回滚。
func (s *Service) selectSchedulingHost(ctx context.Context, tx pgx.Tx, resources schedulingResources, image string, generation int, network string) (SchedulingDecision, error) {
	policy, err := readPolicy(ctx, tx, true)
	if err != nil {
		return SchedulingDecision{}, err
	}
	position, err := readSchedulerPosition(ctx, tx, true)
	if err != nil {
		return SchedulingDecision{}, err
	}
	args := schedulingArgs(resources, image, generation, network)
	items, err := loadSchedulingCandidates(ctx, tx, args)
	if err != nil {
		return SchedulingDecision{}, err
	}
	rankSchedulingCandidates(items, policy.SchedulingStrategy, position)
	eligible := 0
	for _, c := range items {
		if c.Eligible {
			eligible++
		}
	}
	for _, candidate := range items {
		if !candidate.Eligible {
			continue
		}
		locked, err := scanSchedulingCandidate(tx.QueryRow(ctx, schedulingCandidatesSQL+` WHERE h.id=$7::uuid FOR UPDATE OF h`, append(args, candidate.ID)...))
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return SchedulingDecision{}, err
		}
		if !locked.Eligible {
			continue
		}
		var selected time.Time
		if err = tx.QueryRow(ctx, `UPDATE scheduler_state SET sequence=sequence+1,last_host_id=$1,last_host_name=$2,last_host_created_at=$3,last_scheduled_at=clock_timestamp() WHERE singleton RETURNING last_scheduled_at`, locked.ID, locked.Name, locked.CreatedAt).Scan(&selected); err != nil {
			return SchedulingDecision{}, err
		}
		if _, err = tx.Exec(ctx, `UPDATE hosts SET last_scheduled_sequence=$2,last_scheduled_at=$3 WHERE id=$1::uuid`, locked.ID, position.Sequence+1, selected); err != nil {
			return SchedulingDecision{}, err
		}
		return SchedulingDecision{Strategy: policy.SchedulingStrategy, HostID: locked.ID, HostName: locked.Name, Sequence: position.Sequence + 1, SelectedAt: selected, Reason: schedulingReason(policy.SchedulingStrategy, locked), ProjectedCPU: locked.ProjectedCPU, ProjectedMemory: locked.ProjectedMemory, ProjectedDisk: locked.ProjectedDisk, EligibleHosts: eligible}, nil
	}
	return SchedulingDecision{}, errors.New("没有同时满足资源预算、实时安全余量、镜像和网络就绪条件的可调度宿主机")
}

func (s *Service) SchedulingStatus(ctx context.Context) (schedulerPosition, error) {
	return readSchedulerPosition(ctx, s.DB, false)
}

// 只读一致性快照，不锁调度进度、不预占资源、不生成密码或任务。
func (s *Service) PreviewScheduling(ctx context.Context, in SchedulingRequest) (map[string]any, error) {
	if in.FlavorID == "" || in.ImageID == "" || !uuidPattern.MatchString(in.NetworkID) {
		return nil, invalidSchedulingInput("请选择规格、镜像和有效网络")
	}
	if in.Strategy != "" && !validSchedulingStrategy(in.Strategy) {
		return nil, invalidSchedulingInput("调度策略无效")
	}
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	p, err := readPolicy(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	if in.Strategy == "" {
		in.Strategy = p.SchedulingStrategy
	}
	var resources schedulingResources
	var generation int
	if err = tx.QueryRow(ctx, `SELECT cpu,memory_mb,disk_gb FROM flavors WHERE id=$1 AND enabled`, in.FlavorID).Scan(&resources.CPU, &resources.MemoryMB, &resources.DiskGB); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, invalidSchedulingInput("规格不存在或未启用")
		}
		return nil, err
	}
	if err = tx.QueryRow(ctx, `SELECT generation FROM images WHERE id=$1 AND enabled AND sync_status='READY'`, in.ImageID).Scan(&generation); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, invalidSchedulingInput("镜像不存在、未启用或未就绪")
		}
		return nil, err
	}
	var enabled bool
	if err = tx.QueryRow(ctx, `SELECT enabled FROM networks WHERE id=$1::uuid`, in.NetworkID).Scan(&enabled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, invalidSchedulingInput("网络不存在或未启用")
		}
		return nil, err
	}
	if !enabled {
		return nil, invalidSchedulingInput("网络不存在或未启用")
	}
	position, err := readSchedulerPosition(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	items, err := loadSchedulingCandidates(ctx, tx, schedulingArgs(resources, in.ImageID, generation, in.NetworkID))
	if err != nil {
		return nil, err
	}
	rankSchedulingCandidates(items, in.Strategy, position)
	var selected any
	reason := "没有满足条件的宿主机，请查看各宿主排除原因"
	if len(items) > 0 && items[0].Eligible {
		selected = items[0].ID
		reason = schedulingReason(in.Strategy, items[0])
	}
	return map[string]any{"strategy": in.Strategy, "saved_strategy": p.SchedulingStrategy, "selected_host_id": selected, "reason": reason, "hosts": items, "resources": resources, "notice": "预览不预占资源、不检查用户配额或 IP 可用性；最终结果以实际提交时检查为准"}, tx.Commit(ctx)
}
