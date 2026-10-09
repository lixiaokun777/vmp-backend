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

type ImageObservation struct {
	ImageID    string `json:"image_id"`
	FileName   string `json:"file_name"`
	Checksum   string `json:"checksum"`
	Generation int    `json:"generation"`
	Status     string `json:"status"`
	Error      string `json:"error"`
}
type NetworkObservation struct {
	Bridge string `json:"bridge"`
	Ready  bool   `json:"ready"`
	Error  string `json:"error"`
}

var imageDigestPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// 全局短事务锁统一镜像定义、清单上报和任务完成的锁顺序，避免 image/host_images 死锁。
func LockResourceReadiness(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(73124509168))
	return err
}

func safeObservationMessage(value string) string {
	if strings.Contains(strings.ToLower(value), "http://") || strings.Contains(strings.ToLower(value), "https://") {
		return "远程资源请求失败，请检查连接、权限或摘要；敏感地址不回显"
	}
	runes := []rune(value)
	if len(runes) > 512 {
		runes = runes[:512]
	}
	return string(runes)
}

// 就绪清单必须对应本次完整目录探测；陈旧代次或不匹配摘要不能重新启用镜像。
func (s *Service) observeReadinessTx(ctx context.Context, tx pgx.Tx, hostID string, facts HostFacts, at time.Time) error {
	if !facts.ReadinessComplete {
		return nil
	}
	seen := []string{}
	for _, observation := range facts.Images {
		var generation int
		var fileName, checksum string
		err := tx.QueryRow(ctx, `SELECT generation,file_name,coalesce(checksum,'') FROM images WHERE id=$1`, observation.ImageID).Scan(&generation, &fileName, &checksum)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		seen = append(seen, observation.ImageID)
		status := strings.ToUpper(observation.Status)
		message := safeObservationMessage(observation.Error)
		if status != "READY" && status != "MISSING" && status != "FAILED" {
			status = "MISSING"
		}
		if generation != observation.Generation || fileName != observation.FileName {
			status = "STALE"
			message = "镜像定义已变更，等待当前代次重新检查"
		}
		if status == "READY" && (!imageDigestPattern.MatchString(observation.Checksum) || checksum != "" && !strings.EqualFold(checksum, observation.Checksum)) {
			status = "FAILED"
			message = "镜像摘要不匹配，不能交付"
		}
		if status != "READY" {
			var syncing bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tasks WHERE host_id=$1::uuid AND task_type='SYNC_IMAGE' AND status IN ('PENDING','RUNNING') AND payload->>'image_id'=$2 AND payload->>'image_generation'=$3)`, hostID, observation.ImageID, fmt.Sprint(generation)).Scan(&syncing); err != nil {
				return err
			}
			if syncing {
				status = "SYNCING"
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO host_images(host_id,image_id,generation,file_name,checksum,status,error,reported_at,verified_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $6='READY' THEN $8::timestamptz ELSE NULL END) ON CONFLICT(host_id,image_id) DO UPDATE SET generation=excluded.generation,file_name=excluded.file_name,checksum=excluded.checksum,status=excluded.status,error=excluded.error,reported_at=excluded.reported_at,verified_at=excluded.verified_at`, hostID, observation.ImageID, observation.Generation, fileName, strings.ToLower(observation.Checksum), status, message, at); err != nil {
			return err
		}
		if err := refreshImageStateTx(ctx, tx, observation.ImageID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE host_images hi SET status='STALE',error='完整清单未报告该镜像',verified_at=NULL WHERE host_id=$1::uuid AND NOT(image_id=ANY($2::text[])) AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.host_id=hi.host_id AND t.task_type='SYNC_IMAGE' AND t.status IN ('PENDING','RUNNING') AND t.payload->>'image_id'=hi.image_id)`, hostID, seen); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE host_networks SET ready=false,error='本次完整清单未报告网桥',reported_at=$2 WHERE host_id=$1::uuid`, hostID, at); err != nil {
		return err
	}
	for _, network := range facts.Networks {
		if _, err := tx.Exec(ctx, `INSERT INTO host_networks(host_id,network_id,bridge,ready,error,reported_at) SELECT $1::uuid,n.id,n.bridge,$3,$4,$5 FROM networks n WHERE n.bridge=$2 ON CONFLICT(host_id,network_id) DO UPDATE SET bridge=excluded.bridge,ready=excluded.ready,error=excluded.error,reported_at=excluded.reported_at`, hostID, network.Bridge, network.Ready, safeObservationMessage(network.Error), at); err != nil {
			return err
		}
	}
	return nil
}

func refreshImageStateTx(ctx context.Context, tx pgx.Tx, imageID string) error {
	_, err := tx.Exec(ctx, `UPDATE images im SET sync_status=CASE WHEN source_type='local' THEN 'READY' WHEN EXISTS(SELECT 1 FROM host_images hi WHERE hi.image_id=im.id AND hi.generation=im.generation AND hi.status='READY' AND hi.file_name=im.file_name AND lower(hi.checksum)=lower(im.checksum) AND hi.reported_at>now()-interval '120 seconds') THEN 'READY' WHEN EXISTS(SELECT 1 FROM host_images hi WHERE hi.image_id=im.id AND hi.generation=im.generation AND hi.status='SYNCING') THEN 'SYNCING' WHEN EXISTS(SELECT 1 FROM host_images hi WHERE hi.image_id=im.id AND hi.generation=im.generation AND hi.status='FAILED') THEN 'FAILED' ELSE 'PENDING' END WHERE id=$1`, imageID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE images SET enabled=desired_enabled AND (source_type='local' OR sync_status='READY') WHERE id=$1`, imageID)
	return err
}

// 镜像任务的资源是宿主 UUID，不能把它当作实例执行删除、状态修正或租约恢复。
func (s *Service) applyImageSyncResultTx(ctx context.Context, tx pgx.Tx, taskID, hostID string, result TaskResult) error {
	var payload struct {
		ImageID    string `json:"image_id"`
		Checksum   string `json:"checksum"`
		FileName   string `json:"file_name"`
		Generation int    `json:"image_generation"`
	}
	var raw []byte
	var taskStatus string
	if err := tx.QueryRow(ctx, `SELECT payload,status FROM tasks WHERE id=$1::uuid`, taskID).Scan(&raw, &taskStatus); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	status, message := "FAILED", safeObservationMessage(result.Error)
	if result.Success {
		if result.ImageID != payload.ImageID || result.ImageGeneration != payload.Generation || result.ImageFileName != payload.FileName || !strings.EqualFold(result.ImageChecksum, payload.Checksum) {
			return errors.New("镜像同步结果与任务代次或摘要不匹配")
		}
		status, message = "READY", ""
	} else if taskStatus == "PENDING" {
		status = "SYNCING"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO host_images(host_id,image_id,generation,file_name,checksum,status,error,reported_at,verified_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,now(),CASE WHEN $6='READY' THEN now() ELSE NULL END) ON CONFLICT(host_id,image_id) DO UPDATE SET generation=excluded.generation,file_name=excluded.file_name,checksum=excluded.checksum,status=excluded.status,error=excluded.error,reported_at=now(),verified_at=excluded.verified_at WHERE host_images.generation<=excluded.generation`, hostID, payload.ImageID, payload.Generation, payload.FileName, payload.Checksum, status, message); err != nil {
		return err
	}
	return refreshImageStateTx(ctx, tx, payload.ImageID)
}

func (s *Service) QueueImageSync(ctx context.Context, imageID string, hostIDs []string) (map[string]any, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := LockResourceReadiness(ctx, tx); err != nil {
		return nil, err
	}
	var sourceURL, checksum, fileName, sourceType string
	var generation int
	if err = tx.QueryRow(ctx, `SELECT source_type,source_location,checksum,file_name,generation FROM images WHERE id=$1 FOR UPDATE`, imageID).Scan(&sourceType, &sourceURL, &checksum, &fileName, &generation); err != nil {
		return nil, errors.New("镜像不存在或缺少同步信息")
	}
	if sourceType != "remote" {
		return nil, errors.New("本地镜像由完整心跳探测就绪，不通过远程下载任务修改")
	}
	rows, err := tx.Query(ctx, `SELECT h.id::text FROM hosts h JOIN host_credentials c ON c.host_id=h.id WHERE h.agent_mode='kvm' AND c.revoked_at IS NULL AND ($1::uuid[]='{}' OR h.id=ANY($1::uuid[])) ORDER BY h.id FOR UPDATE OF h`, hostIDs)
	if err != nil {
		return nil, err
	}
	var targets []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		targets = append(targets, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("没有可同步的已认证写模式宿主机")
	}
	queued, ready := 0, 0
	for _, hostID := range targets {
		var available bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM host_images WHERE host_id=$1::uuid AND image_id=$2 AND generation=$3 AND status='READY' AND checksum=$4 AND reported_at>now()-interval '120 seconds')`, hostID, imageID, generation, strings.ToLower(checksum)).Scan(&available); err != nil {
			return nil, err
		}
		if available {
			ready++
			continue
		}
		payload, _ := json.Marshal(map[string]any{"image_id": imageID, "source_url": sourceURL, "checksum": strings.ToLower(checksum), "file_name": fileName, "image_generation": generation})
		if _, err = tx.Exec(ctx, `INSERT INTO tasks(idempotency_key,task_type,resource_id,host_id,payload) VALUES($1,'SYNC_IMAGE',$2::uuid,$2::uuid,$3) ON CONFLICT(idempotency_key) DO UPDATE SET status='PENDING',attempt=0,result=NULL,error_message=NULL,claim_token=NULL,lease_until=NULL,claimed_at=NULL,completed_at=NULL,available_at=now(),updated_at=now() WHERE tasks.status NOT IN ('PENDING','RUNNING')`, fmt.Sprintf("image-sync:%s:%s:%d", hostID, imageID, generation), hostID, payload); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO host_images(host_id,image_id,generation,file_name,checksum,status) VALUES($1::uuid,$2,$3,$4,$5,'SYNCING') ON CONFLICT(host_id,image_id) DO UPDATE SET generation=excluded.generation,file_name=excluded.file_name,checksum=excluded.checksum,status='SYNCING',error='',verified_at=NULL,reported_at=now()`, hostID, imageID, generation, fileName, strings.ToLower(checksum)); err != nil {
			return nil, err
		}
		queued++
	}
	if err = refreshImageStateTx(ctx, tx, imageID); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"queued": queued, "already_ready": ready, "generation": generation}, nil
}

// 完整且授权的域观察仅修正稳定电源状态；缺失不删除记录、IP、磁盘或预算。
func (s *Service) reconcileDomainObservationsTx(ctx context.Context, tx pgx.Tx, hostID string, domains []Domain, complete bool, at time.Time) error {
	if !complete {
		return nil
	}
	seen := []string{}
	for _, domain := range domains {
		if domain.Ownership != "MANAGED" || !uuidPattern.MatchString(domain.PlatformInstanceID) {
			continue
		}
		state := normalizeDomainState(domain.State)
		delivery := normalizeDeliveryStatus(domain.DeliveryStatus)
		tag, err := tx.Exec(ctx, `UPDATE instances i SET observed_domain_status=$4,provider_status=$4,last_domain_seen_at=$5,domain_missing_since=NULL,domain_missing_scans=0,delivery_status=CASE WHEN $6<>'UNKNOWN' THEN $6 WHEN $4 NOT IN ('RUNNING','STOPPED') THEN 'DEGRADED' ELSE delivery_status END,delivery_message=CASE WHEN $6<>'UNKNOWN' THEN $7 ELSE delivery_message END,lifecycle_status=CASE WHEN lifecycle_status IN ('RUNNING','STOPPED') AND expires_at>now() AND retention_until IS NULL AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.resource_id=i.id AND t.status IN ('PENDING','RUNNING')) AND $4 IN ('RUNNING','STOPPED') THEN $4 ELSE lifecycle_status END,updated_at=now() WHERE id=$1::uuid AND host_id=$2::uuid AND name=$3 AND (provider_ref IS NULL OR provider_ref=$8)`, domain.PlatformInstanceID, hostID, domain.Name, state, at, delivery, safeObservationMessage(domain.DeliveryMessage), domain.ProviderUUID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			seen = append(seen, domain.PlatformInstanceID)
		}
	}
	_, err := tx.Exec(ctx, `UPDATE instances SET domain_missing_scans=domain_missing_scans+1,domain_missing_since=coalesce(domain_missing_since,$3),provider_status=CASE WHEN domain_missing_scans>=2 AND coalesce(domain_missing_since,$3)<=$3::timestamptz-interval '30 seconds' THEN 'MISSING' ELSE provider_status END,delivery_status=CASE WHEN domain_missing_scans>=2 AND coalesce(domain_missing_since,$3)<=$3::timestamptz-interval '30 seconds' THEN 'DEGRADED' ELSE delivery_status END,delivery_message=CASE WHEN domain_missing_scans>=2 AND coalesce(domain_missing_since,$3)<=$3::timestamptz-interval '30 seconds' THEN '连续完整清单未找到托管域，请管理员核查；资源与IP仍保留' ELSE delivery_message END WHERE host_id=$1::uuid AND NOT(id=ANY($2::uuid[])) AND lifecycle_status IN ('RUNNING','STOPPED')`, hostID, seen, at)
	return err
}
func normalizeDomainState(state string) string {
	value := strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(state)), " ", "_")
	switch value {
	case "RUNNING", "BLOCKED":
		return "RUNNING"
	case "SHUT_OFF", "SHUTOFF", "STOPPED":
		return "STOPPED"
	case "PAUSED", "PMSUSPENDED", "CRASHED":
		return value
	default:
		return "UNKNOWN"
	}
}
func normalizeDeliveryStatus(status string) string {
	switch strings.ToUpper(status) {
	case "READY", "NETWORK_PENDING", "GUEST_PENDING", "DEGRADED", "FAILED":
		return strings.ToUpper(status)
	default:
		return "UNKNOWN"
	}
}
