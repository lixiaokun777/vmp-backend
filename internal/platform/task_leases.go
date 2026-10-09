package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrTaskClaimConflict = errors.New("任务领取凭证已失效或结果与已确认结果冲突")

func taskResultHashes(result TaskResult) (string, string) {
	claim := sha256.Sum256([]byte(result.ClaimToken))
	result.ClaimToken = ""
	data, _ := json.Marshal(result)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(claim[:]), hex.EncodeToString(digest[:])
}

// RenewTaskLease 只有仍持有有效租约的尝试可以续租，旧令牌不可重新夺回任务。
func (s *Service) RenewTaskLease(ctx context.Context, hostID, taskID, token string) (time.Time, error) {
	if token == "" {
		return time.Time{}, ErrTaskClaimConflict
	}
	var until time.Time
	err := s.DB.QueryRow(ctx, `UPDATE tasks SET lease_until=now()+interval '60 seconds',updated_at=now() WHERE id=$1::uuid AND host_id=$2::uuid AND status='RUNNING' AND claim_token=$3 AND lease_until>now() RETURNING lease_until`, taskID, hostID, token).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrTaskClaimConflict
	}
	return until, err
}

// RecoverTaskLeases 保守重排可幂等执行的任务；重启结果不确定时绝不再次自动重启。
func (s *Service) RecoverTaskLeases(ctx context.Context) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text,resource_id::text,task_type,attempt,max_attempts FROM tasks WHERE status='RUNNING' AND lease_until<=now() ORDER BY lease_until FOR UPDATE SKIP LOCKED LIMIT 50`)
	if err != nil {
		return err
	}
	type expiredTask struct {
		id, resourceID, taskType string
		attempt, maxAttempts     int
	}
	var tasks []expiredTask
	for rows.Next() {
		var task expiredTask
		if err = rows.Scan(&task.id, &task.resourceID, &task.taskType, &task.attempt, &task.maxAttempts); err != nil {
			rows.Close()
			return err
		}
		tasks = append(tasks, task)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, task := range tasks {
		message := "任务租约过期，已重新排队等待宿主机安全重试"
		terminal := task.attempt >= task.maxAttempts || task.taskType == "REBOOT_INSTANCE"
		if terminal {
			message = "任务租约过期且结果不确定，请核查实例实际状态后再操作"
			if _, err = tx.Exec(ctx, `UPDATE tasks SET status='FAILED',error_message=$1,completed_at=now(),lease_until=NULL,updated_at=now() WHERE id=$2::uuid`, message, task.id); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE instances SET lifecycle_status=$1,updated_at=now() WHERE id=$2::uuid`, terminalFailureStatus(task.taskType), task.resourceID); err != nil {
				return err
			}
			if task.taskType == "CREATE_INSTANCE" || task.taskType == "START_INSTANCE" {
				if _, err = tx.Exec(ctx, `UPDATE approval_requests SET status='APPROVED_FAILED',result=coalesce(result,'{}'::jsonb)||jsonb_build_object('error',$1::text),updated_at=now() WHERE instance_id=$2::uuid AND status='APPROVED' AND ((request_type='CREATE' AND $3='CREATE_INSTANCE') OR (request_type='RESTORE' AND $3='START_INSTANCE'))`, message, task.resourceID, task.taskType); err != nil {
					return err
				}
			}
		} else {
			if _, err = tx.Exec(ctx, `UPDATE tasks SET status='PENDING',claim_token=NULL,lease_until=NULL,claimed_at=NULL,error_message=$1,available_at=now(),updated_at=now() WHERE id=$2::uuid`, message, task.id); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,outcome,detail) VALUES('system','task.lease_expired','task',$1,'FAILED',jsonb_build_object('task_type',$2::text,'terminal',$3::boolean))`, task.id, task.taskType, terminal); err != nil {
			return err
		}
	}
	// 回执只留摘要，保留 60 天覆盖离线 Agent 的确认重试，分批清理避免长事务。
	if _, err = tx.Exec(ctx, `DELETE FROM task_completion_receipts WHERE (task_id,claim_token_hash) IN (SELECT task_id,claim_token_hash FROM task_completion_receipts WHERE created_at<now()-interval '60 days' LIMIT 500)`); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
