package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const approvalThresholdHours = 7 * 24

var instanceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9-]{1,48}$`)

func (s *Service) CreateApplication(ctx context.Context, actor string, in CreateApplicationInput) (map[string]any, error) {
	if in.LeaseHours <= approvalThresholdHours {
		return s.createApplicationNow(ctx, actor, in)
	}
	if !instanceNamePattern.MatchString(in.InstanceName) || strings.TrimSpace(in.Purpose) == "" || in.LeaseHours > 720 {
		return nil, errors.New("申请参数无效")
	}
	if in.NetworkID == "" {
		if err := s.DB.QueryRow(ctx, `SELECT id::text FROM networks WHERE enabled ORDER BY created_at LIMIT 1`).Scan(&in.NetworkID); err != nil {
			return nil, errors.New("没有可用网络")
		}
	}
	var valid bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flavors WHERE id=$1 AND enabled) AND EXISTS(SELECT 1 FROM images WHERE id=$2 AND enabled AND sync_status='READY') AND EXISTS(SELECT 1 FROM networks WHERE id=$3::uuid AND enabled)`, in.FlavorID, in.ImageID, in.NetworkID).Scan(&valid)
	if err != nil || !valid {
		return nil, errors.New("规格、镜像或网络不可用")
	}
	var duplicate bool
	if err := s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM instances WHERE lower(name)=lower($1)) OR EXISTS(SELECT 1 FROM approval_requests WHERE request_type='CREATE' AND status IN ('PENDING','PROCESSING') AND lower(payload->>'instance_name')=lower($1))`, in.InstanceName).Scan(&duplicate); err != nil {
		return nil, err
	}
	if duplicate {
		return nil, errors.New("实例名称已存在或正在审批")
	}
	payload, _ := json.Marshal(in)
	return s.insertApproval(ctx, actor, "CREATE", "", in.LeaseHours, in.Purpose, payload)
}

func (s *Service) RenewInstance(ctx context.Context, actor string, administrator bool, instanceID string, hours int, reason string) (map[string]any, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, errors.New("请填写续期原因")
	}
	if hours <= approvalThresholdHours {
		return s.renewInstanceNow(ctx, actor, administrator, instanceID, hours, reason)
	}
	return s.submitInstanceApproval(ctx, actor, administrator, instanceID, "RENEW", hours, reason)
}

func (s *Service) RestoreInstance(ctx context.Context, actor string, administrator bool, instanceID string, hours int, reason string) (map[string]any, error) {
	if hours < 1 || hours > 720 || !uuidPattern.MatchString(instanceID) {
		return nil, errors.New("实例或恢复租期无效")
	}
	if strings.TrimSpace(reason) == "" {
		return nil, errors.New("请填写恢复原因")
	}
	if hours > approvalThresholdHours {
		return s.submitInstanceApproval(ctx, actor, administrator, instanceID, "RESTORE", hours, reason)
	}
	return s.restoreInstanceNow(ctx, actor, administrator, instanceID, hours, reason)
}

func (s *Service) submitInstanceApproval(ctx context.Context, actor string, administrator bool, instanceID, requestType string, hours int, reason string) (map[string]any, error) {
	if hours < 1 || hours > 720 || !uuidPattern.MatchString(instanceID) {
		return nil, errors.New("实例或租期无效")
	}
	var owner, name, lifecycleStatus string
	var restoreCount int
	var retentionUntil *time.Time
	err := s.DB.QueryRow(ctx, `SELECT a.applicant,i.name,i.lifecycle_status,i.retention_until,i.restore_count FROM instances i JOIN applications a ON a.id=i.application_id WHERE i.id=$1::uuid`, instanceID).Scan(&owner, &name, &lifecycleStatus, &retentionUntil, &restoreCount)
	if err != nil {
		return nil, errors.New("实例不存在")
	}
	if owner != actor && !administrator {
		return nil, errors.New("实例不属于当前用户")
	}
	if requestType == "RESTORE" {
		if restoreCount >= 1 {
			return nil, errors.New("该实例已使用过一次保留期恢复，不能再次恢复")
		}
		if lifecycleStatus != "RETAINED" || retentionUntil == nil || !retentionUntil.After(time.Now()) {
			return nil, errors.New("只有仍在保留期内的实例可以恢复")
		}
	} else if lifecycleStatus == "RETAINED" {
		return nil, errors.New("保留期实例请使用恢复操作")
	} else if lifecycleStatus != "RUNNING" && lifecycleStatus != "STOPPED" {
		return nil, fmt.Errorf("当前状态 %s 不能续期", lifecycleStatus)
	}
	payload, _ := json.Marshal(map[string]any{"instance_id": instanceID, "instance_name": name, "hours": hours, "reason": reason})
	return s.insertApproval(ctx, actor, requestType, instanceID, hours, reason, payload)
}

func (s *Service) insertApproval(ctx context.Context, actor, requestType, instanceID string, hours int, reason string, payload []byte) (map[string]any, error) {
	var id, requestNo string
	var expiresAt time.Time
	err := s.DB.QueryRow(ctx, `INSERT INTO approval_requests(request_no,request_type,applicant,instance_id,requested_hours,reason,payload) VALUES('APR-'||to_char(now(),'YYYYMMDD')||'-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,6)),$1,$2,nullif($3,'')::uuid,$4,$5,$6) RETURNING id::text,request_no,expires_at`, requestType, actor, instanceID, hours, reason, payload).Scan(&id, &requestNo, &expiresAt)
	if err != nil {
		if strings.Contains(err.Error(), "approval_requests_pending_instance_idx") {
			return nil, errors.New("该实例已有同类型审批正在处理")
		}
		return nil, err
	}
	detail, _ := json.Marshal(map[string]any{"request_no": requestNo, "request_type": requestType, "requested_hours": hours})
	_, _ = s.DB.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'approval.submit','approval',$2,$3)`, actor, id, detail)
	return map[string]any{"id": id, "request_no": requestNo, "request_type": requestType, "requested_hours": hours, "status": "PENDING", "expires_at": expiresAt, "approval_required": true}, nil
}

func (s *Service) restoreInstanceNow(ctx context.Context, actor string, administrator bool, instanceID string, hours int, reason string) (map[string]any, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var owner, hostID, name, lifecycleStatus string
	var restoreCount int
	var retentionUntil *time.Time
	err = tx.QueryRow(ctx, `SELECT a.applicant,i.host_id::text,i.name,i.lifecycle_status,i.retention_until,i.restore_count FROM instances i JOIN applications a ON a.id=i.application_id WHERE i.id=$1::uuid FOR UPDATE OF i`, instanceID).Scan(&owner, &hostID, &name, &lifecycleStatus, &retentionUntil, &restoreCount)
	if err != nil {
		return nil, err
	}
	if owner != actor && !administrator {
		return nil, errors.New("实例不属于当前用户")
	}
	if lifecycleStatus != "RETAINED" || retentionUntil == nil || !retentionUntil.After(time.Now()) {
		return nil, errors.New("实例不在可恢复的保留期内")
	}
	if restoreCount >= 1 {
		return nil, errors.New("该实例已使用过一次保留期恢复，不能再次恢复")
	}
	var activeTasks int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE resource_id=$1::uuid AND status IN ('PENDING','RUNNING')`, instanceID).Scan(&activeTasks); err != nil {
		return nil, err
	}
	if activeTasks > 0 {
		return nil, errors.New("实例仍有任务正在执行")
	}
	if err := insertInstanceTask(ctx, tx, "START_INSTANCE", instanceID, hostID, name, reason); err != nil {
		return nil, err
	}
	var expiresAt time.Time
	if err := tx.QueryRow(ctx, `UPDATE instances SET expires_at=now()+make_interval(hours=>$1),retention_until=NULL,lifecycle_status='STARTING',restore_count=restore_count+1,updated_at=now() WHERE id=$2::uuid RETURNING expires_at`, hours, instanceID).Scan(&expiresAt); err != nil {
		return nil, err
	}
	detail, _ := json.Marshal(map[string]any{"hours": hours, "reason": reason, "expires_at": expiresAt, "original_ip_retained": true})
	_, _ = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'instance.restore','instance',$2,$3)`, actor, instanceID, detail)
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"id": instanceID, "status": "STARTING", "expires_at": expiresAt, "approval_required": false}, nil
}

func (s *Service) DecideApproval(ctx context.Context, reviewer, approvalID, decision, comment string, adjustedHours int) (map[string]any, error) {
	decision = strings.ToUpper(strings.TrimSpace(decision))
	if !uuidPattern.MatchString(approvalID) || (decision != "APPROVE" && decision != "REJECT") {
		return nil, errors.New("审批参数无效")
	}
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, err
	}
	var requestType, applicant, instanceID string
	var requestedHours int
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT request_type,applicant,coalesce(instance_id::text,''),requested_hours,payload FROM approval_requests WHERE id=$1::uuid AND status='PENDING' AND expires_at>now() FOR UPDATE`, approvalID).Scan(&requestType, &applicant, &instanceID, &requestedHours, &payload)
	if err != nil {
		tx.Rollback(ctx)
		return nil, errors.New("审批单已被其他管理员处理或已经超时")
	}
	if adjustedHours > 0 {
		if adjustedHours > 720 {
			tx.Rollback(ctx)
			return nil, errors.New("调整后的租期必须在 1-720 小时之间")
		}
		requestedHours = adjustedHours
		if _, err := tx.Exec(ctx, `UPDATE approval_requests SET requested_hours=$1,payload=jsonb_set(payload,CASE WHEN request_type='CREATE' THEN '{lease_hours}'::text[] ELSE '{hours}'::text[] END,to_jsonb($1::integer),true),updated_at=now() WHERE id=$2::uuid`, requestedHours, approvalID); err != nil {
			tx.Rollback(ctx)
			return nil, err
		}
	}
	if decision == "REJECT" {
		if strings.TrimSpace(comment) == "" {
			tx.Rollback(ctx)
			return nil, errors.New("拒绝时必须填写原因")
		}
		_, err = tx.Exec(ctx, `UPDATE approval_requests SET status='REJECTED',reviewer=$1,review_comment=$2,reviewed_at=now(),updated_at=now() WHERE id=$3::uuid`, reviewer, comment, approvalID)
		if err != nil {
			tx.Rollback(ctx)
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'approval.reject','approval',$2,jsonb_build_object('comment',$3::text))`, reviewer, approvalID, comment); err != nil {
			tx.Rollback(ctx)
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return map[string]any{"id": approvalID, "status": "REJECTED"}, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE approval_requests SET status='PROCESSING',reviewer=$1,review_comment=$2,reviewed_at=now(),updated_at=now() WHERE id=$3::uuid`, reviewer, comment, approvalID); err != nil {
		tx.Rollback(ctx)
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	var result map[string]any
	switch requestType {
	case "CREATE":
		var input CreateApplicationInput
		input, err = decodeCreateApprovalPayload(payload, requestedHours)
		if err != nil {
			err = errors.New("创建申请负载无效")
		} else {
			result, err = s.createApplicationNow(ctx, applicant, input)
		}
	case "RENEW":
		result, err = s.renewInstanceNow(ctx, applicant, true, instanceID, requestedHours, "审批通过："+comment)
	case "RESTORE":
		result, err = s.restoreInstanceNow(ctx, applicant, true, instanceID, requestedHours, "审批通过："+comment)
	default:
		err = errors.New("不支持的审批类型")
	}
	if err != nil {
		_, _ = s.DB.Exec(ctx, `UPDATE approval_requests SET status='FAILED',result=jsonb_build_object('error',$1),updated_at=now() WHERE id=$2::uuid`, err.Error(), approvalID)
		return nil, err
	}
	delete(result, "connection")
	resultPayload, _ := json.Marshal(result)
	resultInstanceID := instanceID
	if value, ok := result["instance_id"].(string); ok {
		resultInstanceID = value
	} else if value, ok := result["id"].(string); ok {
		resultInstanceID = value
	}
	_, err = s.DB.Exec(ctx, `UPDATE approval_requests SET status='APPROVED',instance_id=nullif($1,'')::uuid,result=$2,updated_at=now() WHERE id=$3::uuid`, resultInstanceID, resultPayload, approvalID)
	if err != nil {
		return nil, err
	}
	detail, _ := json.Marshal(map[string]any{"request_type": requestType, "applicant": applicant, "comment": comment, "approved_hours": requestedHours})
	_, _ = s.DB.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'approval.approve','approval',$2,$3)`, reviewer, approvalID, detail)
	return map[string]any{"id": approvalID, "status": "APPROVED", "result": result}, nil
}

func decodeCreateApprovalPayload(payload []byte, approvedHours int) (CreateApplicationInput, error) {
	var input CreateApplicationInput
	if err := json.Unmarshal(payload, &input); err != nil {
		return CreateApplicationInput{}, err
	}
	input.LeaseHours = approvedHours
	return input, nil
}

func (s *Service) WithdrawApproval(ctx context.Context, actor, approvalID string) error {
	if !uuidPattern.MatchString(approvalID) {
		return errors.New("审批单编号无效")
	}
	tag, err := s.DB.Exec(ctx, `UPDATE approval_requests SET status='WITHDRAWN',updated_at=now() WHERE id=$1::uuid AND applicant=$2 AND status='PENDING' AND expires_at>now()`, approvalID, actor)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("审批单不存在、已处理或已超时")
	}
	_, _ = s.DB.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'approval.withdraw','approval',$2,'{}'::jsonb)`, actor, approvalID)
	return nil
}

func (s *Service) ResubmitApprovalShort(ctx context.Context, actor string, administrator bool, approvalID string, hours int, reason string) (map[string]any, error) {
	if !uuidPattern.MatchString(approvalID) || hours < 1 || hours > approvalThresholdHours || strings.TrimSpace(reason) == "" {
		return nil, errors.New("短租期必须在 1-168 小时之间，并填写重提原因")
	}
	var requestType, applicant, instanceID string
	var payload []byte
	err := s.DB.QueryRow(ctx, `SELECT request_type,applicant,coalesce(instance_id::text,''),payload FROM approval_requests WHERE id=$1::uuid AND status IN ('REJECTED','EXPIRED','FAILED','WITHDRAWN')`, approvalID).Scan(&requestType, &applicant, &instanceID, &payload)
	if err != nil {
		return nil, errors.New("只有被拒绝、超时、执行失败或已撤回的审批单可以改为短租期重提")
	}
	if applicant != actor && !administrator {
		return nil, errors.New("审批单不属于当前用户")
	}
	var result map[string]any
	switch requestType {
	case "CREATE":
		var input CreateApplicationInput
		if err := json.Unmarshal(payload, &input); err != nil {
			return nil, errors.New("创建申请负载无效")
		}
		input.LeaseHours = hours
		result, err = s.createApplicationNow(ctx, applicant, input)
	case "RENEW":
		result, err = s.renewInstanceNow(ctx, applicant, administrator, instanceID, hours, reason)
	case "RESTORE":
		result, err = s.restoreInstanceNow(ctx, applicant, administrator, instanceID, hours, reason)
	default:
		err = errors.New("不支持的审批类型")
	}
	if err != nil {
		return nil, err
	}
	detail, _ := json.Marshal(map[string]any{"hours": hours, "reason": reason})
	_, _ = s.DB.Exec(ctx, `UPDATE approval_requests SET result=result||jsonb_build_object('short_resubmitted',true,'short_hours',$1::integer),updated_at=now() WHERE id=$2::uuid`, hours, approvalID)
	_, _ = s.DB.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'approval.resubmit_short','approval',$2,$3)`, actor, approvalID, detail)
	return result, nil
}

func (s *Service) ExpirePendingApprovals(ctx context.Context) error {
	_, err := s.DB.Exec(ctx, `WITH expired AS (UPDATE approval_requests SET status='EXPIRED',result=jsonb_build_object('error','超过 24 小时未审批，申请已自动关闭'),updated_at=now() WHERE status='PENDING' AND expires_at<=now() RETURNING id::text) INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) SELECT 'system','approval.expire','approval',id,'{"reason":"24h_timeout"}'::jsonb FROM expired`)
	return err
}
