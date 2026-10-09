# API 说明

## 服务器分页与资源就绪（0.5.1）

`GET /users`、`GET /instances`、`GET /approvals`、`GET /ip-addresses`返回 `{items,total,page,page_size}`，默认1页/20条，上限100，越界页夹到最后一页；总数和记录使用同一只读快照。所有支持keyword；users额外role/source/status，instances额外status/host_id/scope=mine，approvals额外status/type/scope=mine，IP必填network_id并支持status。完整枚举和字段见 [资源就绪与服务器分页](资源就绪与服务器分页.md)。普通用户始终限自己的实例/审批，scope=all不能越权。

instances额外返回全授权scope的 `expiring_total`（未来24h，不受分页/关键词/状态筛选截断）；IP直接返回owner/lifecycle_status/allocated_at/reserved_at。管理员flavors有usage聚合，不从当前页或同名规格猜占用。

宿主报告 `budget_source=CONFIGURED_TOTAL`、`resource_measured_at`、安全可分配余量、当前代次镜像和网桥就绪，调度同时检查固定预算-预留与实际安全余量及就绪矩阵。`GET /agents/{id}/catalog`须对应独立凭据；管理员 `POST /images/{id}/sync` 请求显式host_ids（1-128），按宿主和代次幂等同步。远程仅HTTPS+SHA256，内容寻址缓存不覆盖在用backing。

实例详情有delivery_status/message、observed_domain_status、last_domain_seen_at、console_available；生命周期RUNNING不等同完整交付。未到期、实际存在且新鲜确认的托管域在PROVISIONING/ERROR等状态可签发救援票据；签发/连接都复核权限、期限和域，浏览器只连接同源WS桥，最长5分钟且不超过实例期限，不自动开机。

用户CRUD与LDAP同步在串行事务中保护至少一个启用LOCAL应急管理员；无本地管理员的旧环境须提供新未占用bootstrap管理员名和强密码，不自动提升/重启旧账号。

## 群通知（仅管理员）

后端 0.4.5 起自动与测试消息均使用 Markdown，发送记录中的 message 为原始 Markdown 文本。配置和接口结构不变，不向群发送敏感凭据。具体样式见 [群通知](群通知.md)。

- `GET /api/v1/notifications/config`：读取规则、打码地址和最近发送结果，不返回明文凭据。
- `PUT /api/v1/notifications/config`：保存 `enabled`、`webhook_url`、`signature_secret`、`platform_url`、`reminder_hours`、`notify_retained`、`notify_retention_end`、`mention_owner`；0.5.1 增加 `notify_approvals`、`notify_failures`、`notify_host_alerts`，旧客户端省略时保留原值。凭据留空保持不变，`clear_webhook` / `clear_signature_secret` 可清除。提醒时间为 1–168 小时、最多 5 个不重复整数。
- `POST /api/v1/notifications/test`：向已保存机器人发送测试消息，自动通知关闭时仍可测试，至少间隔 3 秒；成功后须到群确认收件。
- `GET /api/v1/notifications/events?page=1&status=SENT`：每页 20 条，支持 `PENDING`、`SENT`、`FAILED`、`CANCELLED` 筛选。

未登录返回 401，普通用户返回 403，配置不合法返回 422，测试限频返回 429、机器人错误返回 502。配置及测试写入审计但不记录凭据，自动发送默认关闭。详见 [群通知](群通知.md)。

## 登录与用户

登录保护自后端 0.4.4 起默认开启：同 IP 每分钟最多 30 次；同来源账号 15 分钟最多 5 次。超限返回 429、中文错误及 Retry-After 秒数；保护存储异常返回 503。未知账号适用相同规则。详细代理配置见 [登录保护](登录保护.md)。

- `POST /api/v1/auth/login`：请求通过 `source=LOCAL|LDAP` 明确选择平台账号或 LDAP 账号；账号来源不匹配时拒绝登录。成功后写入 HttpOnly 会话 Cookie。
- `POST /api/v1/auth/logout`、`GET /api/v1/auth/me`：退出登录和读取当前账号。
- `POST /api/v1/auth/password`：本地用户修改自己的密码，修改成功后清理该账号的其他登录会话。
- `GET/POST/PATCH/DELETE /api/v1/users`：管理员查询、创建、更新和删除用户。
- `POST /api/v1/users/{id}/password`：管理员重置本地用户密码并清除其现有会话。
- `GET /api/v1/ldap/status`、`PUT /api/v1/ldap/config`：管理员查看并保存 LDAP 配置，响应不返回绑定密码。
- `POST /api/v1/ldap/test`、`POST /api/v1/ldap/sync`：管理员测试目录连接并分页同步用户。`users.enabled` 为平台主动启停，`ldap_directory_present` 为目录存在状态；同步不会重新启用平台停用的账号。两者都允许才可登录或沿用会话。

LDAP 登录使用已转义用户名和 `login_filter` 实际搜索 Base DN，必须唯一匹配且用户名属性一致，再以本次查询 DN 验证密码。零匹配、多匹配、跨用户结果均拒绝；不再按旧同步 DN 直接绑定。LDAP 连接、请求及调用方取消均有期限，目录服务无响应时会退出。

除健康检查、登录和 Agent 通信外，所有接口均要求有效会话。管理员可访问全部平台管理接口；普通用户只可读取申请所需的规格、镜像和网络，提交申请，查看自己的审批单，并查看、续期、恢复或操作自己的实例。服务端不信任客户端传入的用户名。

所有依赖 Cookie 会话的非 GET/HEAD 写请求必须额外携带 `X-VMP-Request: 1`，缺失或不匹配返回 403 中文安全校验提示。平台前端自动设置；自行调用 API 的 curl/脚本必须显式设置，不要放宽 CORS 或移除校验来兼容旧脚本。健康检查、普通 GET/HEAD 读取和 Agent 的引导/独立 Bearer 通信不受此头要求影响。

管理员 Cookie 写接口调用示例（cookie 文件需受限保存，凭据响应不要输出到共享日志）：

```bash
curl -sS -b /受限路径/session.cookies \
  -H 'Content-Type: application/json' \
  -H 'X-VMP-Request: 1' \
  -X POST 'https://平台域名/api/v1/ldap/sync'
```

## 业务接口

- `GET /api/v1/health`：健康检查。
- `GET /api/v1/summary`：资源总览。
- `GET /api/v1/hosts`、`PATCH /api/v1/hosts/{id}/status`：宿主机列表和状态管理。默认只返回真实宿主机；`GET /api/v1/hosts?all=1` 可用于开发诊断并包含 mock 节点。
- `PATCH /api/v1/hosts/{id}/quota`：在 Agent 安全上限内设置平台 CPU、内存和磁盘调度配额。
- `DELETE /api/v1/hosts/{id}`：删除已离线且没有未释放实例和执行中任务的宿主机纳管记录，不操作外部虚机。
- `GET/POST/PATCH/DELETE /api/v1/flavors`：资源规格管理。规格/镜像标识必须以字母或数字开头，仅支持字母、数字、点、下划线和连字符，最长 64 字符。被引用的规格可编辑用于未来申请，但既有实例资源快照不变，不能删除仍被申请记录引用的规格。
- `GET/POST/PATCH/DELETE /api/v1/images`：镜像元数据管理。删除只移除平台元数据，不删除宿主机镜像文件；已被引用的镜像不能删除。`PATCH` 可编辑名称、系统版本和来源字段，变更来源增加generation并使旧就绪记录失效。本地镜像提供 `source_location`，Agent 强制其位于 `KVM_IMAGE_ROOT` 内；远程镜像只接受HTTPS URL和SHA-256，显式选择宿主后以SYNC_IMAGE任务下载校验，不接受HTTP/userinfo用户名密码。Agent域名白名单与私网准入见Agent配置文档。
- `GET/POST/PATCH/DELETE /api/v1/networks`：管理员同时定义网段、网关、DNS、Bridge 和唯一有效的 `ip_range_start` / `ip_range_end`。修改范围会事务性替换旧的空闲地址池；新范围之外存在已分配、预留或隔离地址时拒绝修改。仍有非空闲 IP 的网络不能删除。
- `POST/DELETE /api/v1/networks/{id}/ip-ranges`：兼容旧客户端的地址池增删接口；Web 管理端统一通过网络编辑接口维护唯一范围。
- `GET /api/v1/ip-addresses`：查询 IP 资源池。
- `POST /api/v1/applications`：提交虚拟机申请。租期不超过 168 小时自动调度，并在 `connection` 中返回 IP、用户名和仅显示一次的初始密码；超过 168 小时返回 `approval_required=true`，批准前不预占资源。
- `GET /api/v1/instances`：活动实例列表；已完成删除的实例不会返回。`scope=mine` 仅查询当前用户。返回 `flavor_id`、创建时的 `flavor` 名称和 `resource_snapshot={cpu,memory_mb,disk_gb}`，不使用当前规格配置覆盖既有实例。默认排除 mock 节点的开发数据，诊断时可增加 `all=1`。
- `GET /api/v1/instances/{id}`：实例配置、租期、任务历史和审计记录。
- `POST /api/v1/instances/{id}/actions`：提交 `start`、`stop`、`reboot`、`reset_password`、`retry`、`release` 或 `force_delete` 操作。`reset_password` 仅允许运行中且新交付已READY的实例（历史UNKNOWN兼容），响应返回只显示一次的新密码，任务负载只保存密码摘要。普通释放保留磁盘和原 IP 7 天；`force_delete` 跳过保留期。删除任务成功后释放IP/预算并清理资源和任务记录，平台审计证据按历史策略保留。`retry` 在同事务恢复必要IP预留再复位创建任务，资源预算不重复记账；不确定执行或已有域但缺IP时拒绝盲目重建。
- `POST /api/v1/instances/{id}/renew`：按小时续期，允许 1-720 小时并必须填写 `reason`；超过 168 小时进入审批。
- `POST /api/v1/instances/{id}/restore`：恢复仍在 7 天保留期内的实例，必须填写 `reason`；复用原磁盘和原 IP且每台实例最多恢复一次，恢复租期超过 168 小时进入审批。
- `GET /api/v1/approvals`：普通用户只能查看自己的审批单；管理员查看全部审批单，可用 `status` 筛选，`scope=mine` 查看本人提交。
- `POST /api/v1/approvals/{id}/decision`：管理员批准或拒绝审批，`decision=APPROVE|REJECT`；拒绝必须填写 `comment`，批准可用 `adjusted_hours` 调整租期，调整值会覆盖创建、续期或恢复操作的实际执行租期。接口只处理仍为待审批且未超时的记录，避免重复批准。
- `POST /api/v1/approvals/batch-decision`：管理员批量批准或拒绝最多 50 个审批单，逐条返回执行结果。
- `POST /api/v1/approvals/{id}/withdraw`：申请人撤回仍为待审批的申请。
- `POST /api/v1/approvals/{id}/resubmit-short`：被拒绝、超时、执行失败或主动撤回后，申请人改为不超过 168 小时的短租期并立即执行。
- `POST /api/v1/instances/{id}/console-sessions`：请求 `mode=vnc|serial`，仅实例所有者或管理员可用。返回同源平台 WebSocket 地址和 5 分钟有效的一次性票据；0.5.1 基于实际存在的授权托管域提供创建中/错误现场救援，不接管外部域，不绕过到期/保留/删除限制。
- `POST /api/v1/agents/{id}/console-sessions/{sessionID}/consume`：Agent 使用运行令牌原子核销一次性票据，仅供内部调用。
- `GET /api/v1/audit-logs`：管理员查询平台操作流水，支持 `keyword`、`action`、`resource_type`、`outcome`、`scope`、`from`、`to`、`page`和 `page_size`，并返回动态动作与资源类型选项。

## Agent 接口

- `POST /api/v1/agents/register`：新的唯一宿主名称用 `X-Bootstrap-Token` 首次纳管，返回 `id/name/status/runtime_token`，独立运行凭据只返回一次。已有名称必须用 `Authorization: Bearer <该宿主运行凭据>` 恢复纳管，响应不重新返回或修改凭据；可携带 `host_id` 加验，bootstrap 不可接管旧宿主。
- `POST /api/v1/agents/{id}/heartbeat`：独立宿主身份上报事实、检查项和域清单。
- `GET /api/v1/agents/{id}/catalog`：独立身份读取当前镜像/网络定义；完整探测后回报 `readiness_complete`、镜像代次/摘要和网桥就绪。控制面只向该宿主信任的 Agent 提供这些配置。
- `POST /api/v1/images/{id}/sync`：管理员提交 `{host_ids:["宿主UUID"]}`，1–128 台目标；实际下载由各宿主 Agent 的 `SYNC_IMAGE` 执行，返回排队/已就绪计数。本地镜像不使用下载任务，而由完整心跳检查。
- `GET /api/v1/agents/{id}/tasks/next`：独立宿主身份领取待执行任务，返回 `claim_token` 和 `lease_until` 执行租约。
- `POST /api/v1/agents/{id}/tasks/{taskID}/renew`：以 `{claim_token}` 为当前执行续租，返回 `{lease_until}`。旧/冲突领取凭据返回 409。
- `POST /api/v1/agents/{id}/tasks/{taskID}/result`：以当前 `claim_token` 上报结果；相同已确认结果可重试，冲突或旧领取凭据返回 409，保存失败返回 500，可继续重试。
- `POST /api/v1/hosts/{id}/credentials/rotate`：管理员签发/轮换该宿主独立凭据，返回 `host_id/name/runtime_token/generation`。旧凭据立即失效，新值仅返回一次；宿主暂停新增调度，更新 Agent 并确认心跳后再手动恢复。
- `POST /api/v1/hosts/{id}/credentials/revoke`：管理员吊销宿主身份并暂停新增调度，不操作已有虚拟机。

所有 Agent 任务、心跳及控制台核销接口均按独立凭据绑定 URL `{id}`，无全局运行令牌回退。跨宿主、无效/已吊销凭据返回 401；普通用户不能轮换或吊销。数据库仅存 SHA-256 摘要；旧宿主升级步骤见 [身份与凭据加固](身份与凭据加固.md)。

控制台浏览器连接 `GET /api/v1/console/{vnc|serial}?ticket=...`，要求有效 Cookie、精确同源 Origin 和属于当前账号的签名票据；不能将票据转给另一个账号使用。控制面基于新鲜托管域事实及租期校验后固定拨号宿主纳管 IP。Agent 仍在升级握手前原子核销，平台不提前核销造成双重消费。

## 创建任务负载

`CREATE_INSTANCE` 任务包含实例 UUID、名称、CPU、内存、磁盘、`image_file`、网桥、稳定生成的 `mac_address`、IP、前缀长度、网关、DNS、用户名和 `password_hash`。密码摘要由 PostgreSQL `pgcrypto` 生成，明文不写入任务、实例表或审计日志。

Agent 在创建磁盘/定义域前结合 ARP 与 ICMP 探测候选 IP，占用时返回 `error_code=IP_ADDRESS_IN_USE`。控制面隔离冲突地址、预留下一个空闲地址并更新任务。池耗尽会明确失败；管理员扩容后重试会补齐 IP 关系。Guest Agent、目标 MAC 和网络可用性分层报告交付，单独 ping 超时不删现场。详细能力与限制见 [P2 功能与验收](P2功能与验收.md)。

## 治理接口（0.5.1）

- `GET/PUT /api/v1/platform-policy`：仅管理员。字段 `max_instances/max_cpu/max_memory_mb/max_disk_gb/max_future_lease_hours/max_continuous_lease_hours` 的 0 表示不限；`auto_renew_enabled` 默认 false，`auto_renew_hours` 为 1–168、`auto_renew_max_count` 为 1–100；`audit_retention_days/notification_retention_days/approval_retention_days` 为 0 永久，非零至少 180/30/90 天。
- `GET/PUT /api/v1/instances/{id}/auto-renew`：所有者或管理员。保存 `{enabled,hours,max_renewals}`，响应含成功次数、停止原因及平台是否开启、最大小时/次数；重新开关不重置次数。到期前一小时检查，不对已到期实例自动恢复。
- `GET/PUT /api/v1/approval-delegation`：当前管理员自己的代理；读取返回 `delegation` 与有效管理员列表。保存 `{delegate_username,starts_at,ends_at}`，时间为 RFC3339、最长 90 天；空用户名取消。禁止自代理/重叠链式代理。
- `POST /api/v1/approvals/{id}/transfer`：管理员将 pending 且未过期单据转给有效管理员，`{reviewer_username,reason}` 必填。审批列表显示 `assigned_reviewer/delegated_from`；其他有效管理员仍可应急处理。
- `GET/POST /api/v1/history/archives`：管理员查最近 100 份归档或生成 `{category:"audit"|"notifications"|"approvals"}`。每批最多 5000 行/32 MiB 原文，返回 ID、行数和压缩文件 SHA-256。
- `GET /api/v1/history/archives/{id}/download`：下载 gzip NDJSON，`X-Archive-SHA256` 提供校验值。
- `POST /api/v1/history/archives/{id}/purge`：提交 `{checksum,confirm:"已下载并校验归档"}`，只删本批精确 ID、未改变且达到当前期限的终态记录；保留归档，返回 `deleted_count`。
- `DELETE /api/v1/history/archives/{id}`：源记录已清理、下载备份后提交 `{checksum,confirm:"已备份归档"}`，不可恢复地删除归档副本。所有操作留审计，永久保留或活跃数据拒绝清理。

配额检查与实例预占同事务、用户级锁保护；保留期/错误待清理实例计入资源额度。超过 168 小时的规则仍是单次申请或延长，不把连续短续期自动改判成审批；未来和连续总期限由管理员显式配置。

`START_INSTANCE`、`STOP_INSTANCE`、`REBOOT_INSTANCE` 和 `DELETE_INSTANCE` 只下发实例 UUID、域名和触发原因。到期实例会先关机并进入 7 天保留期；保留期结束后才下发删除任务、释放 IP 和宿主机配额。

`RESET_INSTANCE_PASSWORD` 下发实例 UUID、域名、系统用户名和 crypt 密码摘要。明文新密码只存在于本次 HTTP 响应，不写入任务、实例表或审计日志。

申请成功响应示例：

```json
{
  "request_no": "REQ-20260929-ABC123",
  "instance_id": "123e4567-e89b-42d3-a456-426614174000",
  "status": "APPROVED",
  "connection": {
    "ip_address": "192.168.50.100",
    "username": "ubuntu",
    "password": "仅在本次响应中返回",
    "available_after_provisioning": true
  }
}
```

当前为内网第一版协议，已启用用户身份认证和角色授权。正式上线前还需通过 HTTPS/WSS 传输会话，并定期轮换 Agent 令牌和控制台签名密钥。
