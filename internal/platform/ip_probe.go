package platform

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
)

const maxIPProbeBatch = 64

var ErrIPRecoveryQueued = errors.New("隔离地址复核已排队")

func probeMessage(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	return safeObservationMessage(strings.Join(strings.Fields(value), " "))
}

func requireProbeAdministrator(ctx context.Context, tx pgx.Tx, actor string) error {
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1 AND role='ADMIN' AND enabled AND NOT must_change_password AND (source<>'LDAP' OR ldap_directory_present))`, actor).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return errors.New("管理员身份已失效，请重新登录")
	}
	return nil
}

// queueIPProbeTx 固定地址、网桥及凭据代次；同一IP同时只允许一个复核，不升级既有请求的解除权限。
func (s *Service) queueIPProbeTx(ctx context.Context, tx pgx.Tx, ipID, preferredHost, actor string, release bool, recoveryInstance string) (string, string, bool, error) {
	ipID = strings.ToLower(ipID)
	preferredHost = strings.ToLower(preferredHost)
	recoveryInstance = strings.ToLower(recoveryInstance)
	var address, network, state, bridge string
	var bound bool
	if err := tx.QueryRow(ctx, `SELECT host(ip.address),ip.network_id::text,ip.status,ip.instance_id IS NOT NULL,n.bridge FROM ip_addresses ip JOIN networks n ON n.id=ip.network_id WHERE ip.id=$1::uuid FOR UPDATE OF ip`, ipID).Scan(&address, &network, &state, &bound, &bridge); err != nil {
		return "", "", false, err
	}
	if state != "QUARANTINED" || bound {
		return "", "", false, errors.New("只能复核未绑定实例的隔离IP；已分配、预留和保留期IP不能解除")
	}
	var existing string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM tasks WHERE resource_id=$1::uuid AND task_type='PROBE_IP_ADDRESS' AND status IN ('PENDING','RUNNING') ORDER BY created_at LIMIT 1`, ipID).Scan(&existing); err == nil {
		return existing, address, true, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, err
	}
	var hostID string
	var generation int64
	err := tx.QueryRow(ctx, `SELECT h.id::text,c.generation FROM hosts h JOIN host_credentials c ON c.host_id=h.id AND c.revoked_at IS NULL JOIN host_networks hn ON hn.host_id=h.id AND hn.network_id=$1::uuid AND hn.ready AND hn.bridge=$2 AND hn.reported_at>now()-interval '120 seconds' WHERE h.agent_mode='kvm' AND h.status IN ('ACTIVE','CORDONED') AND h.last_heartbeat_at>now()-interval '45 seconds' AND ($3='' OR h.id::text=$3) ORDER BY (h.status='ACTIVE') DESC,h.name LIMIT 1`, network, bridge, preferredHost).Scan(&hostID, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, errors.New("没有具备独立身份和新鲜网桥状态的可执行探测宿主；只读宿主不会执行任务")
	}
	if err != nil {
		return "", "", false, err
	}
	payload, err := json.Marshal(map[string]any{"ip_id": ipID, "network_id": network, "ip_address": address, "bridge": bridge, "release_if_free": release, "requested_by": actor, "retry_instance_id": recoveryInstance, "credential_generation": generation})
	if err != nil {
		return "", "", false, err
	}
	var taskID string
	if err = tx.QueryRow(ctx, `INSERT INTO tasks(idempotency_key,task_type,resource_id,host_id,payload,max_attempts) VALUES('ip-probe:'||gen_random_uuid()::text,'PROBE_IP_ADDRESS',$1::uuid,$2::uuid,$3,1) RETURNING id::text`, ipID, hostID, payload).Scan(&taskID); err != nil {
		return "", "", false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE ip_addresses SET last_probe_status='PENDING',last_probe_at=NULL,last_probe_message='已排队，等待宿主机复核',last_probe_host_id=$2::uuid,updated_at=now() WHERE id=$1::uuid`, ipID, hostID); err != nil {
		return "", "", false, err
	}
	return taskID, address, false, nil
}

func (s *Service) ProbeIPAddress(ctx context.Context, actor, ipID string, release bool) (map[string]any, error) {
	if !uuidPattern.MatchString(ipID) {
		return nil, errors.New("IP标识无效")
	}
	ipID = strings.ToLower(ipID)
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = LockResourceReadiness(ctx, tx); err != nil {
		return nil, err
	}
	if err = requireProbeAdministrator(ctx, tx, actor); err != nil {
		return nil, err
	}
	task, address, pending, err := s.queueIPProbeTx(ctx, tx, ipID, "", actor, release, "")
	if err != nil {
		return nil, err
	}
	message := "已提交复核；只有本次确认空闲且选择解除时，才会恢复为可分配IP"
	if pending {
		message = "该IP已有复核任务，沿用原任务；原任务的解除选项不会被更改"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'ip.probe.request','ip_address',$2,jsonb_build_object('task_id',$3::text,'release_if_free',$4::boolean,'already_pending',$5::boolean))`, actor, ipID, task, release, pending); err != nil {
		return nil, err
	}
	return map[string]any{"task_id": task, "ip_address": address, "probe_pending": true, "already_pending": pending, "message": message}, tx.Commit(ctx)
}

func (s *Service) ProbeQuarantinedNetwork(ctx context.Context, actor, network string, release bool, limit int) (map[string]any, error) {
	if !uuidPattern.MatchString(network) || limit < 1 || limit > maxIPProbeBatch {
		return nil, errors.New("网络或复核数量无效；每批1至64个地址")
	}
	network = strings.ToLower(network)
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = LockResourceReadiness(ctx, tx); err != nil {
		return nil, err
	}
	if err = requireProbeAdministrator(ctx, tx, actor); err != nil {
		return nil, err
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM networks WHERE id=$1::uuid)`, network).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("网络不存在")
	}
	rows, err := tx.Query(ctx, `SELECT ip.id::text FROM ip_addresses ip WHERE ip.network_id=$1::uuid AND ip.status='QUARANTINED' AND ip.instance_id IS NULL AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.resource_id=ip.id AND t.task_type='PROBE_IP_ADDRESS' AND t.status IN ('PENDING','RUNNING')) ORDER BY ip.last_probe_at NULLS FIRST,ip.address FOR UPDATE OF ip SKIP LOCKED LIMIT $2`, network, limit)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	tasks := make([]string, 0, len(ids))
	for _, id := range ids {
		task, _, _, e := s.queueIPProbeTx(ctx, tx, id, "", actor, release, "")
		if e != nil {
			return nil, e
		}
		tasks = append(tasks, task)
	}
	var pending, remaining, confirmedInUse int
	if err = tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE EXISTS(SELECT 1 FROM tasks t WHERE t.resource_id=ip.id AND t.task_type='PROBE_IP_ADDRESS' AND t.status IN ('PENDING','RUNNING'))),count(*) FILTER(WHERE last_probe_status IN ('UNKNOWN','ERROR') AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.resource_id=ip.id AND t.task_type='PROBE_IP_ADDRESS' AND t.status IN ('PENDING','RUNNING'))),count(*) FILTER(WHERE last_probe_status='IN_USE') FROM ip_addresses ip WHERE network_id=$1::uuid AND status='QUARANTINED' AND instance_id IS NULL`, network).Scan(&pending, &remaining, &confirmedInUse); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'network.probe_quarantined','network',$2,jsonb_build_object('queued',$3::integer,'release_if_free',$4::boolean,'limit',$5::integer))`, actor, network, len(tasks), release, limit); err != nil {
		return nil, err
	}
	return map[string]any{"queued": len(tasks), "skipped": pending - len(tasks), "limit": limit, "max_limit": maxIPProbeBatch, "remaining": remaining, "confirmed_in_use": confirmedInUse, "task_ids": tasks, "message": "已异步复核隔离地址；remaining仅表示未复核或异常待复核数量，确认占用的地址继续隔离"}, tx.Commit(ctx)
}

// 队列在同一事务中推进，探测异常立即停止；真实占用只尝试有限的下一候选。
func (s *Service) queueNextRecoveryProbeTx(ctx context.Context, tx pgx.Tx, instanceID string) error {
	var host, network, owner string
	var attempts int
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT i.host_id::text,i.network_id::text,ap.applicant,i.ip_recovery_attempts,i.lifecycle_status='ERROR' AND i.expires_at>now() AND EXISTS(SELECT 1 FROM users u WHERE lower(u.username)=lower(ap.applicant) AND u.enabled AND (u.source<>'LDAP' OR u.ldap_directory_present)) AND NOT EXISTS(SELECT 1 FROM discovered_instances d WHERE d.platform_instance_id=i.id AND d.ownership='MANAGED') FROM instances i JOIN applications ap ON ap.id=i.application_id WHERE i.id=$1::uuid FOR UPDATE OF i`, instanceID).Scan(&host, &network, &owner, &attempts, &valid); err != nil {
		return err
	}
	if !valid || attempts >= maxIPProbeBatch {
		return s.stopIPRecoveryTx(ctx, tx, instanceID, "原实例已过期、已被撤销或达到单次64个候选上限；未重新创建")
	}
	var ipID string
	err := tx.QueryRow(ctx, `SELECT ip.id::text FROM ip_addresses ip JOIN instances i ON i.id=$2::uuid WHERE ip.network_id=$1::uuid AND ip.status='QUARANTINED' AND ip.instance_id IS NULL AND NOT(ip.id=ANY(i.ip_recovery_tried)) AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.resource_id=ip.id AND t.task_type='PROBE_IP_ADDRESS' AND t.status IN ('PENDING','RUNNING')) ORDER BY ip.address FOR UPDATE OF ip SKIP LOCKED LIMIT 1`, network, instanceID).Scan(&ipID)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.stopIPRecoveryTx(ctx, tx, instanceID, "暂时没有可复核的空闲候选，地址仍被占用或正在复核；请查看网络复核结果后重试")
	}
	if err != nil {
		return err
	}
	task, _, _, err := s.queueIPProbeTx(ctx, tx, ipID, host, owner, false, instanceID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE instances SET ip_recovery_pending=true,ip_recovery_attempts=ip_recovery_attempts+1,ip_recovery_tried=array_append(ip_recovery_tried,$2::uuid),ip_recovery_task_id=$3::uuid,ip_recovery_message='正在复核隔离地址，确认空闲后自动重试原创建任务',delivery_status='QUEUED',delivery_message='隔离地址复核中，尚未重新创建',updated_at=now() WHERE id=$1::uuid`, instanceID, ipID, task)
	return err
}

func (s *Service) stopIPRecoveryTx(ctx context.Context, tx pgx.Tx, instanceID, message string) error {
	_, err := tx.Exec(ctx, `UPDATE instances SET ip_recovery_pending=false,ip_recovery_message=$2,delivery_status='FAILED',delivery_message=$2,updated_at=now() WHERE id=$1::uuid AND lifecycle_status='ERROR'`, instanceID, probeMessage(message))
	return err
}

func (s *Service) cancelIPRecoveryTx(ctx context.Context, tx pgx.Tx, instanceID string) error {
	if _, err := tx.Exec(ctx, `UPDATE ip_addresses SET last_probe_status='ERROR',last_probe_at=now(),last_probe_message='原实例操作已取消复核',updated_at=now() WHERE last_probe_status='PENDING' AND id IN(SELECT resource_id FROM tasks WHERE task_type='PROBE_IP_ADDRESS' AND payload->>'retry_instance_id'=$1 AND status IN('PENDING','RUNNING'))`, instanceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE tasks SET status='CANCELLED',completed_at=now(),lease_until=NULL,updated_at=now() WHERE task_type='PROBE_IP_ADDRESS' AND payload->>'retry_instance_id'=$1 AND status IN ('PENDING','RUNNING')`, instanceID); err != nil {
		return err
	}
	return s.stopIPRecoveryTx(ctx, tx, instanceID, "实例操作已取消复核；不会自动重建")
}

func (s *Service) applyIPProbeResultTx(ctx context.Context, tx pgx.Tx, taskID, ipID, hostID string, result TaskResult) error {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT payload FROM tasks WHERE id=$1::uuid AND host_id=$2::uuid AND resource_id=$3::uuid AND task_type='PROBE_IP_ADDRESS'`, taskID, hostID, ipID).Scan(&raw); err != nil {
		return err
	}
	var p struct {
		IPID       string `json:"ip_id"`
		Network    string `json:"network_id"`
		Address    string `json:"ip_address"`
		Bridge     string `json:"bridge"`
		Release    bool   `json:"release_if_free"`
		Actor      string `json:"requested_by"`
		Instance   string `json:"retry_instance_id"`
		Generation int64  `json:"credential_generation"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	var address, network, state, bridge string
	var bound, ready bool
	if err := tx.QueryRow(ctx, `SELECT host(ip.address),ip.network_id::text,ip.status,ip.instance_id IS NOT NULL,n.bridge,n.enabled AND EXISTS(SELECT 1 FROM hosts h JOIN host_credentials c ON c.host_id=h.id AND c.revoked_at IS NULL JOIN host_networks hn ON hn.host_id=h.id AND hn.network_id=ip.network_id WHERE h.id=$2::uuid AND h.agent_mode='kvm' AND h.status IN ('ACTIVE','CORDONED') AND h.last_heartbeat_at>now()-interval '45 seconds' AND c.generation=$3 AND hn.ready AND hn.bridge=n.bridge AND hn.reported_at>now()-interval '120 seconds') FROM ip_addresses ip JOIN networks n ON n.id=ip.network_id WHERE ip.id=$1::uuid FOR UPDATE OF ip`, ipID, hostID, p.Generation).Scan(&address, &network, &state, &bound, &bridge, &ready); err != nil {
		return err
	}
	probe := strings.ToUpper(result.IPProbeStatus)
	message := probeMessage(result.IPProbeMessage)
	if message == "" {
		message = probeMessage(result.Error)
	}
	valid := result.Success && (probe == "FREE" || probe == "IN_USE") && p.IPID == ipID && p.Network == network && p.Address == address && result.IPAddress == address && p.Bridge == bridge && ready && state == "QUARANTINED" && !bound
	if !valid {
		probe = "ERROR"
		message = "探测异常、目标不匹配或地址状态已改变；未解除隔离：" + message
	}
	if message == "" {
		if probe == "FREE" {
			message = "本次新鲜探测确认空闲"
		} else {
			message = "本次探测发现真实占用，继续隔离"
		}
	}
	data, _ := json.Marshal(result)
	taskState := "SUCCEEDED"
	var taskError any
	if probe == "ERROR" {
		taskState = "FAILED"
		taskError = message
	}
	if _, err := tx.Exec(ctx, `UPDATE tasks SET status=$2,result=$3,error_message=$4,completed_at=now(),updated_at=now() WHERE id=$1::uuid`, taskID, taskState, data, taskError); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE ip_addresses SET last_probe_status=$2,last_probe_at=now(),last_probe_message=$3,last_probe_host_id=$4::uuid,updated_at=now() WHERE id=$1::uuid`, ipID, probe, message, hostID); err != nil {
		return err
	}
	released := false
	if probe == "FREE" && p.Release && p.Instance == "" {
		if err := requireProbeAdministrator(ctx, tx, p.Actor); err == nil {
			tag, e := tx.Exec(ctx, `UPDATE ip_addresses SET status='FREE',updated_at=now() WHERE id=$1::uuid AND status='QUARANTINED' AND instance_id IS NULL`, ipID)
			if e != nil {
				return e
			}
			released = tag.RowsAffected() == 1
		} else {
			message += "；申请管理员权限已失效，未解除隔离"
			if _, e := tx.Exec(ctx, `UPDATE ip_addresses SET last_probe_message=$2 WHERE id=$1::uuid`, ipID, message); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `UPDATE tasks SET status='FAILED',error_message=$2 WHERE id=$1::uuid`, taskID, message); e != nil {
				return e
			}
		}
	}
	if p.Instance != "" {
		var active bool
		err := tx.QueryRow(ctx, `SELECT ip_recovery_pending AND ip_recovery_task_id=$2::uuid AND lifecycle_status='ERROR' AND expires_at>now() AND host_id=$3::uuid AND network_id=$4::uuid AND EXISTS(SELECT 1 FROM applications ap JOIN users u ON lower(u.username)=lower(ap.applicant) WHERE ap.id=i.application_id AND ap.applicant=$5 AND u.enabled AND (u.source<>'LDAP' OR u.ldap_directory_present)) AND NOT EXISTS(SELECT 1 FROM discovered_instances d WHERE d.platform_instance_id=i.id AND d.ownership='MANAGED') FROM instances i WHERE id=$1::uuid FOR UPDATE`, p.Instance, taskID, hostID, network, p.Actor).Scan(&active)
		if errors.Is(err, pgx.ErrNoRows) {
			active = false
		} else if err != nil {
			return err
		}
		if active && probe == "FREE" {
			if _, err := tx.Exec(ctx, `UPDATE instances SET ip_recovery_pending=false WHERE id=$1::uuid`, p.Instance); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE ip_addresses SET status='RESERVED',instance_id=$2::uuid,reserved_at=now(),allocated_at=NULL,updated_at=now() WHERE id=$1::uuid AND status='QUARANTINED' AND instance_id IS NULL`, ipID, p.Instance); err != nil {
				return err
			}
			var createTask string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM tasks WHERE resource_id=$1::uuid AND task_type='CREATE_INSTANCE' AND status='FAILED' ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, p.Instance).Scan(&createTask); err != nil {
				return err
			}
			if err := s.retryCreateTx(ctx, tx, p.Instance, hostID, createTask); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE instances SET ip_recovery_pending=false,ip_recovery_message='已确认安全空闲并恢复原IP预留，正在重试创建',updated_at=now() WHERE id=$1::uuid`, p.Instance); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,detail) VALUES($1,'instance.ip_recovery.completed','instance',$2,jsonb_build_object('ip_id',$3::text,'task_id',$4::text))`, p.Actor, p.Instance, ipID, taskID); err != nil {
				return err
			}
		} else if active && probe == "IN_USE" {
			if err := s.queueNextRecoveryProbeTx(ctx, tx, p.Instance); err != nil {
				return err
			}
		} else {
			if err := s.stopIPRecoveryTx(ctx, tx, p.Instance, "复核失败或原实例已过期/已撤销；未重新创建："+message); err != nil {
				return err
			}
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,outcome,detail) VALUES('system','ip.probe.completed','ip_address',$1,$2,jsonb_build_object('status',$3::text,'message',$4::text,'host_id',$5::text,'released',$6::boolean,'task_id',$7::text))`, ipID, map[bool]string{true: "SUCCESS", false: "FAILED"}[probe != "ERROR"], probe, message, hostID, released, taskID)
	return err
}

func (s *Service) failIPProbeLeaseTx(ctx context.Context, tx pgx.Tx, taskID, ipID, message string) error {
	var instance string
	if err := tx.QueryRow(ctx, `SELECT coalesce(payload->>'retry_instance_id','') FROM tasks WHERE id=$1::uuid`, taskID).Scan(&instance); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE ip_addresses SET last_probe_status='ERROR',last_probe_at=now(),last_probe_message=$2,updated_at=now() WHERE id=$1::uuid`, ipID, probeMessage(message)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(actor,action,resource_type,resource_id,outcome,detail) VALUES('system','ip.probe.completed','ip_address',$1,'FAILED',jsonb_build_object('status','ERROR','message',$2::text,'task_id',$3::text))`, ipID, probeMessage(message), taskID); err != nil {
		return err
	}
	if instance != "" {
		return s.stopIPRecoveryTx(ctx, tx, instance, message)
	}
	return nil
}

func (s *Service) applyTerminalTaskFailureTx(ctx context.Context, tx pgx.Tx, taskType, resourceID, message string) error {
	if taskType == "START_INSTANCE" {
		_, err := tx.Exec(ctx, `UPDATE instances SET lifecycle_status=CASE WHEN restore_pending THEN 'RETAINED' ELSE 'STOPPED' END,expires_at=CASE WHEN restore_pending THEN coalesce(restore_previous_expires_at,expires_at) ELSE expires_at END,restore_pending=false,restore_previous_expires_at=NULL,delivery_status='FAILED',delivery_message=$2,updated_at=now() WHERE id=$1::uuid`, resourceID, probeMessage(message))
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE instances SET lifecycle_status=$2,updated_at=now() WHERE id=$1::uuid`, resourceID, terminalFailureStatus(taskType))
	return err
}

func (s *Service) ipRecoveryResponseTx(ctx context.Context, tx pgx.Tx, instanceID string) (map[string]any, error) {
	var pending bool
	var message, task string
	if err := tx.QueryRow(ctx, `SELECT ip_recovery_pending,ip_recovery_message,coalesce(ip_recovery_task_id::text,'') FROM instances WHERE id=$1::uuid`, instanceID).Scan(&pending, &message, &task); err != nil {
		return nil, err
	}
	return map[string]any{"id": instanceID, "status": "ERROR", "recovery_pending": pending, "task_id": task, "message": message}, nil
}
