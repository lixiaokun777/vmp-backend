package platform

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const retentionDuration = 7 * 24 * time.Hour

func retentionAllowed(restoreCount int) bool { return restoreCount == 0 }

// releaseInstanceTx 手动释放和自然到期共用一条规则；只有确认删除后才释放 IP 和资源快照。
func (s *Service) releaseInstanceTx(ctx context.Context, tx pgx.Tx, instanceID, hostID, name, status string, restoreCount int, retentionUntil time.Time, reason string) (map[string]any, error) {
	if status != "RUNNING" && status != "STOPPED" && status != "RETAINED" {
		return nil, errors.New("当前状态不能释放实例")
	}
	if status == "RETAINED" && retentionAllowed(restoreCount) && retentionUntil.After(time.Now()) {
		return map[string]any{"id": instanceID, "status": status, "retention_days": 7}, nil
	}
	retentionDays := 7
	taskType, nextStatus := "", "RETAINED"
	if !retentionAllowed(restoreCount) || !retentionUntil.After(time.Now()) {
		retentionDays = 0
		taskType, nextStatus = "DELETE_INSTANCE", "DELETING"
		retentionUntil = time.Now().UTC()
	} else if status == "RUNNING" {
		taskType, nextStatus = "STOP_INSTANCE", "STOPPING"
	}
	if taskType != "" {
		if err := insertInstanceTask(ctx, tx, taskType, instanceID, hostID, name, reason); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE instances SET lifecycle_status=$1,expires_at=least(expires_at,now()),retention_until=$2,updated_at=now() WHERE id=$3::uuid`, nextStatus, retentionUntil, instanceID); err != nil {
		return nil, err
	}
	return map[string]any{"id": instanceID, "status": nextStatus, "retention_days": retentionDays, "task_type": taskType}, nil
}
