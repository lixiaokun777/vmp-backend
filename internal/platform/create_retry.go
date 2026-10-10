package platform

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// retryCreateTx 在复位任务之前恢复 IP 关系，失败则整体回滚，保留原预算和失败证据。
func (s *Service) retryCreateTx(ctx context.Context, tx pgx.Tx, instanceID, hostID, taskID string) error {
	var unexpired, pending bool
	if err := tx.QueryRow(ctx, `SELECT expires_at>now(),ip_recovery_pending FROM instances WHERE id=$1::uuid`, instanceID).Scan(&unexpired, &pending); err != nil {
		return err
	}
	if !unexpired {
		return errors.New("原申请租期已经结束，不能自动重建；请重新申请或由管理员核查")
	}
	if pending {
		return ErrIPRecoveryQueued
	}
	var raw []byte
	var uncertain bool
	if err := tx.QueryRow(ctx, `SELECT payload,coalesce(result->>'error_code','')='EXECUTION_UNCERTAIN' FROM tasks WHERE id=$1::uuid`, taskID).Scan(&raw, &uncertain); err != nil {
		return err
	}
	if uncertain {
		return errors.New("原执行结果不确定，需管理员先核查托管域，不能直接重复创建")
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return errors.New("原创建负载无效")
	}
	networkID, _ := payload["network_id"].(string)
	if !uuidPattern.MatchString(networkID) {
		return errors.New("原创建任务缺少有效网络，需管理员核查")
	}
	var existingDomain bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM discovered_instances WHERE host_id=$1::uuid AND platform_instance_id=$2::uuid AND ownership='MANAGED') OR EXISTS(SELECT 1 FROM instances WHERE id=$2::uuid AND provider_ref IS NOT NULL) OR EXISTS(SELECT 1 FROM tasks WHERE resource_id=$2::uuid AND task_type='CREATE_INSTANCE' AND coalesce(result->>'provider_ref','')<>'')`, hostID, instanceID).Scan(&existingDomain); err != nil {
		return err
	}
	var address string
	err := tx.QueryRow(ctx, `SELECT host(address) FROM ip_addresses WHERE instance_id=$1::uuid AND status IN ('RESERVED','ALLOCATED') FOR UPDATE`, instanceID).Scan(&address)
	if errors.Is(err, pgx.ErrNoRows) {
		if existingDomain {
			return errors.New("已有托管域但IP关系缺失，需先通过救援控制台核查，不能直接改IP重新创建")
		}
		var ready bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM host_networks hn JOIN networks n ON n.id=hn.network_id WHERE hn.host_id=$1::uuid AND hn.network_id=$2::uuid AND hn.ready AND hn.bridge=n.bridge AND n.enabled AND hn.reported_at>now()-interval '120 seconds')`, hostID, networkID).Scan(&ready); err != nil {
			return err
		}
		if !ready {
			return errors.New("原宿主网络未就绪，请等待管理员修复；原资源仍保留")
		}
		var ipID string
		if err := tx.QueryRow(ctx, `SELECT id::text,host(address) FROM ip_addresses WHERE network_id=$1::uuid AND status='FREE' ORDER BY address FOR UPDATE SKIP LOCKED LIMIT 1`, networkID).Scan(&ipID, &address); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			var pending bool
			if err := tx.QueryRow(ctx, `SELECT ip_recovery_pending FROM instances WHERE id=$1::uuid`, instanceID).Scan(&pending); err != nil {
				return err
			}
			if pending {
				return ErrIPRecoveryQueued
			}
			var quarantined bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ip_addresses WHERE network_id=$1::uuid AND status='QUARANTINED' AND instance_id IS NULL)`, networkID).Scan(&quarantined); err != nil {
				return err
			}
			if !quarantined {
				return errors.New("原网络没有空闲或可复核地址，请管理员检查地址池")
			}
			if _, err := tx.Exec(ctx, `UPDATE instances SET network_id=$2::uuid,ip_recovery_attempts=0,ip_recovery_tried='{}',ip_recovery_task_id=NULL WHERE id=$1::uuid`, instanceID, networkID); err != nil {
				return err
			}
			if err := s.queueNextRecoveryProbeTx(ctx, tx, instanceID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) SELECT ap.applicant,'instance.ip_recovery.request','instance',i.id::text,jsonb_build_object('task_id',i.ip_recovery_task_id) FROM instances i JOIN applications ap ON ap.id=i.application_id WHERE i.id=$1::uuid`, instanceID); err != nil {
				return err
			}
			return ErrIPRecoveryQueued
		}
		if _, err := tx.Exec(ctx, `UPDATE ip_addresses SET status='RESERVED',instance_id=$1::uuid,reserved_at=now(),allocated_at=NULL,updated_at=now() WHERE id=$2::uuid`, instanceID, ipID); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	payload["ip_address"] = address
	updated, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE tasks SET status='PENDING',attempt=0,ip_conflict_count=0,error_message=NULL,result=NULL,payload=$2,available_at=now(),claim_token=NULL,lease_until=NULL,claimed_at=NULL,completed_at=NULL,updated_at=now() WHERE id=$1::uuid`, taskID, updated); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE instances SET lifecycle_status='PROVISIONING',ip_address=$2::inet,network_id=$3::uuid,delivery_status='QUEUED',delivery_message='已恢复IP预留，等待宿主机重新交付',updated_at=now() WHERE id=$1::uuid`, instanceID, address, networkID)
	return err
}
