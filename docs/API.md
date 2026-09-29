# API 说明

## 业务接口

- `GET /api/v1/health`：健康检查。
- `GET /api/v1/summary`：资源总览。
- `GET /api/v1/hosts`、`PATCH /api/v1/hosts/{id}/status`：宿主机列表和状态管理。
- `GET/POST/PATCH /api/v1/flavors`：资源规格管理。
- `GET/POST/PATCH /api/v1/images`：镜像元数据管理；新增镜像必须提供安全的 `file_name`。
- `GET /api/v1/networks`、`GET /api/v1/ip-addresses`：网络和 IP 资源池。
- `POST /api/v1/applications`：提交虚拟机申请；成功时在 `connection` 中返回 IP、用户名和仅显示一次的初始密码。
- `GET /api/v1/instances`：实例列表；`scope=mine` 仅查询当前用户。
- `POST /api/v1/instances/{id}/actions`：提交 `start`、`stop`、`reboot` 或 `release` 操作。
- `POST /api/v1/instances/{id}/renew`：按小时续期，允许 1-720 小时。

## Agent 接口

- `POST /api/v1/agents/register`：引导令牌认证，返回宿主机标识。
- `POST /api/v1/agents/{id}/heartbeat`：上报宿主机事实、检查项和域清单。
- `GET /api/v1/agents/{id}/tasks/next`：领取待执行任务。
- `POST /api/v1/agents/{id}/tasks/{taskID}/result`：上报任务结果。

## 创建任务负载

`CREATE_INSTANCE` 任务包含实例 UUID、名称、CPU、内存、磁盘、`image_file`、网桥、IP、前缀长度、网关、DNS、用户名和 `password_hash`。密码摘要由 PostgreSQL `pgcrypto` 生成，明文不写入任务、实例表或审计日志。

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
