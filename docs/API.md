# API 说明

## 登录与用户

- `POST /api/v1/auth/login`：请求通过 `source=LOCAL|LDAP` 明确选择平台账号或 LDAP 账号；账号来源不匹配时拒绝登录。成功后写入 HttpOnly 会话 Cookie。
- `POST /api/v1/auth/logout`、`GET /api/v1/auth/me`：退出登录和读取当前账号。
- `POST /api/v1/auth/password`：本地用户修改自己的密码，修改成功后清理该账号的其他登录会话。
- `GET/POST/PATCH/DELETE /api/v1/users`：管理员查询、创建、更新和删除用户。
- `POST /api/v1/users/{id}/password`：管理员重置本地用户密码并清除其现有会话。
- `GET /api/v1/ldap/status`、`PUT /api/v1/ldap/config`：管理员查看并保存 LDAP 配置，响应不返回绑定密码。
- `POST /api/v1/ldap/test`、`POST /api/v1/ldap/sync`：管理员测试目录连接并同步用户。

除健康检查、登录和 Agent 通信外，所有接口均要求有效会话。管理员可访问全部平台管理接口；普通用户只可读取申请所需的规格、镜像和网络，提交申请，并查看、续期或操作自己的实例。服务端不信任客户端传入的用户名。

## 业务接口

- `GET /api/v1/health`：健康检查。
- `GET /api/v1/summary`：资源总览。
- `GET /api/v1/hosts`、`PATCH /api/v1/hosts/{id}/status`：宿主机列表和状态管理。默认只返回真实宿主机；`GET /api/v1/hosts?all=1` 可用于开发诊断并包含 mock 节点。
- `PATCH /api/v1/hosts/{id}/quota`：在 Agent 安全上限内设置平台 CPU、内存和磁盘调度配额。
- `DELETE /api/v1/hosts/{id}`：删除已离线且没有未释放实例和执行中任务的宿主机纳管记录，不操作外部虚机。
- `GET/POST/PATCH/DELETE /api/v1/flavors`：资源规格管理。已被申请记录引用的规格只能停用。
- `GET/POST/PATCH/DELETE /api/v1/images`：镜像元数据管理。删除只移除平台元数据，不删除宿主机镜像文件；已被引用的镜像只能停用。`PATCH` 可编辑名称、系统版本和来源字段。本地镜像提供 `source_location`，Agent 强制其位于 `KVM_IMAGE_ROOT` 内；远程镜像提供 HTTP(S) URL 和 SHA-256，创建或修改来源后状态为 `PENDING`。
- `GET/POST/PATCH/DELETE /api/v1/networks`：管理员同时定义网段、网关、DNS、Bridge 和唯一有效的 `ip_range_start` / `ip_range_end`。修改范围会事务性替换旧的空闲地址池；新范围之外存在已分配、预留或隔离地址时拒绝修改。仍有非空闲 IP 的网络不能删除。
- `POST/DELETE /api/v1/networks/{id}/ip-ranges`：兼容旧客户端的地址池增删接口；Web 管理端统一通过网络编辑接口维护唯一范围。
- `GET /api/v1/ip-addresses`：查询 IP 资源池。
- `POST /api/v1/applications`：提交虚拟机申请；成功时在 `connection` 中返回 IP、用户名和仅显示一次的初始密码。
- `GET /api/v1/instances`：活动实例列表；已完成删除的实例不会返回。`scope=mine` 仅查询当前用户。默认排除 mock 节点的开发数据，诊断时可增加 `all=1`。
- `GET /api/v1/instances/{id}`：实例配置、租期、任务历史和审计记录。
- `POST /api/v1/instances/{id}/actions`：提交 `start`、`stop`、`reboot`、`retry`、`release` 或 `force_delete` 操作。普通释放保留磁盘和原 IP 7 天；`force_delete` 跳过保留期。删除任务成功后释放 IP 和宿主机配额，并清除实例、申请、任务与对应审计展示记录。`retry` 仅用于重试已达失败上限的创建任务。
- `POST /api/v1/instances/{id}/renew`：按小时续期，允许 1-720 小时。

## Agent 接口

- `POST /api/v1/agents/register`：引导令牌认证，返回宿主机标识。
- `POST /api/v1/agents/{id}/heartbeat`：上报宿主机事实、检查项和域清单。
- `GET /api/v1/agents/{id}/tasks/next`：领取待执行任务。
- `POST /api/v1/agents/{id}/tasks/{taskID}/result`：上报任务结果。

## 创建任务负载

`CREATE_INSTANCE` 任务包含实例 UUID、名称、CPU、内存、磁盘、`image_file`、网桥、稳定生成的 `mac_address`、IP、前缀长度、网关、DNS、用户名和 `password_hash`。密码摘要由 PostgreSQL `pgcrypto` 生成，明文不写入任务、实例表或审计日志。

`START_INSTANCE`、`STOP_INSTANCE`、`REBOOT_INSTANCE` 和 `DELETE_INSTANCE` 只下发实例 UUID、域名和触发原因。到期实例会先关机并进入 7 天保留期；保留期结束后才下发删除任务、释放 IP 和宿主机配额。

申请成功响应示例：

```json
{
  "request_no": "REQ-20260929-ABC123",
  "instance_id": "123e4567-e89b-42d3-a456-426614174000",
  "status": "APPROVED",
  "connection": {
    "ip_address": "10.200.9.20",
    "username": "ubuntu",
    "password": "仅在本次响应中返回",
    "available_after_provisioning": true
  }
}
```

当前为内网第一版协议，已启用用户身份认证和角色授权。正式上线前还需通过 HTTPS 传输会话 Cookie，并定期轮换 Agent 令牌。
