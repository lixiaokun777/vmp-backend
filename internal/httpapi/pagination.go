package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

type listConditions struct {
	parts []string
	args  []any
}

func (f *listConditions) add(expression string, value any) {
	f.args = append(f.args, value)
	f.parts = append(f.parts, fmt.Sprintf(expression, len(f.args)))
}
func (f *listConditions) where() string {
	if len(f.parts) == 0 {
		return " WHERE true"
	}
	return " WHERE " + strings.Join(f.parts, " AND ")
}

// 总数和页内记录来自同一个只读快照，避免并发删除造成页码、total相互矛盾。
type pageMetadata struct {
	key, query string
	args       []any
}

func (a *API) queryPage(w http.ResponseWriter, r *http.Request, itemSQL, fromSQL, orderSQL string, filter listConditions, extras ...pageMetadata) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if size < 1 || size > 100 {
		size = 20
	}
	tx, err := a.Service.DB.BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		writeError(w, 503, "列表查询暂不可用")
		return
	}
	defer tx.Rollback(r.Context())
	var total int
	if err = tx.QueryRow(r.Context(), "SELECT count(*) "+fromSQL+filter.where(), filter.args...).Scan(&total); err != nil {
		writeError(w, 500, "读取列表总数失败")
		return
	}
	maxPage := max(1, (total+size-1)/size)
	page = min(page, maxPage)
	args := append(append([]any{}, filter.args...), size, (page-1)*size)
	items, err := queryRawList(r, tx, "SELECT "+itemSQL+" "+fromSQL+filter.where()+" "+orderSQL+fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(filter.args)+1, len(filter.args)+2), args...)
	if err != nil {
		writeError(w, 500, "读取列表记录失败")
		return
	}
	response := map[string]any{"items": items, "total": total, "page": page, "page_size": size}
	for _, extra := range extras {
		var value int
		if err := tx.QueryRow(r.Context(), extra.query, extra.args...).Scan(&value); err != nil {
			writeError(w, 500, "读取列表汇总失败")
			return
		}
		response[extra.key] = value
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, 503, "列表快照已失效，请重试")
		return
	}
	writeJSON(w, 200, response)
}

func enumFilter(w http.ResponseWriter, r *http.Request, key string, allowed ...string) (string, bool) {
	value := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get(key)))
	if value == "" || value == "ALL" {
		return "", true
	}
	for _, option := range allowed {
		if value == option {
			return value, true
		}
	}
	writeError(w, 422, "筛选参数无效："+key)
	return "", false
}
