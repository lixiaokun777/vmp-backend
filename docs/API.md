# API 说明

## 业务接口

- `GET /api/v1/health`：健康检查。
- `GET /api/v1/summary`：资源总览。
- `GET /api/v1/hosts`、`PATCH /api/v1/hosts/{id}/status`：宿主机列表和状态管理。默认只返回真实宿主机；`GET /api/v1/hosts?all=1` 可用于开发诊断并包含 mock 节点。
- `PATCH /api/v1/hosts/{id}/quota`：在 Agent 安全上限内设置平台 CPU、内存和磁盘调度配额。
- `DELETE /api/v1/hosts/{id}`：删除已离线且没有未释放实例和执行中任务的宿主机纳管记录，不操作外部虚机。
- `GET/POST/PATCH/DELETE /api/v1/flavors`：资源规格管理。已被申请记录引用的规格只能停用。
- `GET/POST/PATCH/DELETE /api/v1/images`：镜像元数据管理。删除只移除平台元数据，不删除宿主机镜像文件；已被引用的镜像只能停用。`PATCH` 可编辑名称、系统版本和来源字段。本地镜像提供 `source_location`，Agent 强制其位于 `KVM_IMAGE_ROOT` 内；远程镜像提供 HTTP(S) URL 和 SHA-256，创建或修改来源后状态为 `PENDING`。
- `GET/POST/PATCH/DELETE /api/v1/networks`：管理员定义网段、网关、DNS 和 Bridge。仍有非空闲 IP 的网络不能删除。
- `POST /api/v1/networks/{id}/ip-ranges`：向指定网络添加 IP 范围。
- `DELETE /api/v1/networks/{id}/ip-ranges`：删除指定起止地址范围，范围内所有地址必须为空闲。
- `GET /api/v1/ip-addresses`：查询 IP 资源池。
- `POST /api/v1/applications`：提交虚拟机申请；成功时在 `connection` 中返回 IP、用户名和仅显示一次的初始密码。
- `GET /api/v1/instances`：实例列表；`scope=mine` 仅查询当前用户。默认排除 mock 节点的开发数据，诊断时可增加 `all=1`。
- `GET /api/v1/instances/{id}`：实例配置、租期、任务历史和审计记录。
- `POST /api/v1/instances/{id}/actions`：提交 `start`、`stop`、`reboot`、`retry`、`release` 或 `force_delete` 操作。普通释放保留磁盘和原 IP 7 天；`force_delete` 跳过保留期，删除任务成功后释放 IP 和宿主机配额。`retry` 仅用于重试已达失败上限的创建任务。
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

当前为内网第一版协议，正式上线前需要增加用户身份认证、授权和令牌轮换。
