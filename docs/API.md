# API 说明

## 业务接口

- `GET /api/v1/health`：健康检查。
- `GET /api/v1/summary`：资源总览。
- `GET /api/v1/hosts`、`PATCH /api/v1/hosts/{id}/status`：宿主机列表和状态管理。
- `GET/POST/PATCH /api/v1/flavors`：资源规格管理。
- `GET/POST/PATCH /api/v1/images`：镜像元数据管理。
- `GET /api/v1/networks`、`GET /api/v1/ip-addresses`：网络和 IP 资源池。
- `POST /api/v1/applications`：提交虚拟机申请。
- `GET /api/v1/instances`：实例列表；`scope=mine` 仅查询当前用户。

## Agent 接口

- `POST /api/v1/agents/register`：引导令牌认证，返回宿主机标识。
- `POST /api/v1/agents/{id}/heartbeat`：上报宿主机事实、检查项和域清单。
- `GET /api/v1/agents/{id}/tasks/next`：领取待执行任务。
- `POST /api/v1/agents/{id}/tasks/{taskID}/result`：上报任务结果。

当前为内网第一版协议，正式上线前需要增加用户身份认证、授权和令牌轮换。
