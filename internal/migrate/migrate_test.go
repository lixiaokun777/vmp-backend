package migrate

import (
	"regexp"
	"testing"
)

func TestLoadFiles(t *testing.T) {
	files, err := loadFiles()
	if err != nil {
		t.Fatalf("加载迁移文件失败：%v", err)
	}
	if len(files) != 18 {
		t.Fatalf("迁移文件数量错误：得到 %d，期望 18", len(files))
	}

	namePattern := regexp.MustCompile(`^\d{3}_[a-z0-9_]+\.sql$`)
	for index, file := range files {
		if !namePattern.MatchString(file.name) {
			t.Fatalf("迁移文件名不合法：%s", file.name)
		}
		if file.sql == "" || len(file.checksum) != 64 {
			t.Fatalf("迁移文件内容或校验值无效：%s", file.name)
		}
		if index > 0 && files[index-1].name >= file.name {
			t.Fatalf("迁移文件未按名称升序排列：%s 在 %s 之前", files[index-1].name, file.name)
		}
	}
}
