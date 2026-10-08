// Package migrations 提供编译进控制面二进制的数据库迁移文件。
package migrations

import "embed"

// Files 包含控制面启动时按文件名顺序执行的全部 SQL 迁移。
//
//go:embed *.sql
var Files embed.FS
