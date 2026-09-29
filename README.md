# VMP Backend

VMP 虚拟机申领平台的控制面。负责资源规格、镜像、网络 IP、宿主机、申请、实例和 Agent 任务的统一管理。

## 当前能力

- 资源总览和管理列表 API。
- 固定规格、镜像和 IP 资源池。
- 申请创建、主机调度、IP 预留和幂等任务生成。
- Agent 注册、心跳、KVM 存量域发现和任务回传。
- `kvm-readonly` 宿主机强制隔离，不参与调度和任务下发。

## 快速启动

```bash
cp .env.example .env
docker compose up --build
curl http://127.0.0.1:8080/api/v1/health
```

首次启动时 PostgreSQL 会按文件名顺序执行 `migrations/` 中的 SQL。生产环境不应依赖容器首启机制，应使用受控的数据库迁移流程。

## 本地开发

```bash
go test ./...
go run ./cmd/control-plane
```

默认监听 `:8080`，并连接本机 PostgreSQL。所有可配置项见 `.env.example`。

## 文档同步规则

接口、数据表、调度规则、配置或部署方式变更时，同一次提交必须更新 `README.md`、`docs/` 和 `CHANGELOG.md`。项目内人工编写的注释统一使用中文。
