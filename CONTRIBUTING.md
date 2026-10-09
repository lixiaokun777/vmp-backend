# 参与贡献

感谢参与 VMP。提交代码前请先在 Issue 中说明问题或方案，避免重复实现。

1. 从 `main` 创建功能分支。
2. 保持改动聚焦，人工编写的注释和用户文档使用中文。
3. 在专用 PostgreSQL public schema 初始化 pgcrypto，设置 VMP_TEST_DATABASE_URL 后运行 `go test -race -count=1 ./...`、`go vet ./...` 和相关接口验证；未设 DSN 的跳过不算完整数据库回归。
4. 接口、数据表、配置或部署方式变化时，同步更新 `README.md`、`docs/` 和 `CHANGELOG.md`。
5. 提交 Pull Request，写清变更内容、验证方法、兼容性和数据库迁移影响。

禁止提交真实密码、令牌、私钥、生产日志、内网拓扑和个人数据。
