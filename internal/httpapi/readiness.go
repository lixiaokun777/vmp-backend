package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

func (a *API) agentCatalog(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAgent(w, r) {
		return
	}
	images, err := queryRawList(r, a.Service.DB, `SELECT jsonb_build_object('id',id,'source_type',source_type,'source_location',source_location,'file_name',file_name,'checksum',coalesce(checksum,''),'generation',generation,'enabled',desired_enabled) FROM images ORDER BY id`)
	if err != nil {
		writeError(w, 503, "镜像目录暂不可用")
		return
	}
	networks, err := queryRawList(r, a.Service.DB, `SELECT jsonb_build_object('id',id,'bridge',bridge,'cidr',cidr,'enabled',enabled) FROM networks ORDER BY id`)
	if err != nil {
		writeError(w, 503, "网络目录暂不可用")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"images": images, "networks": networks})
}
func (a *API) syncImage(w http.ResponseWriter, r *http.Request) {
	if !resourceIdentifierPattern.MatchString(r.PathValue("id")) {
		writeError(w, 422, "镜像标识无效")
		return
	}
	var input struct {
		HostIDs []string `json:"host_ids"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&input) != nil || len(input.HostIDs) < 1 || len(input.HostIDs) > 128 {
		writeError(w, 422, "请选择1至128台需要同步的宿主机")
		return
	}
	for _, id := range input.HostIDs {
		if _, err := uuid.Parse(id); err != nil {
			writeError(w, 422, "宿主机标识无效")
			return
		}
	}
	result, err := a.Service.QueueImageSync(r.Context(), r.PathValue("id"), input.HostIDs)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, 202, result)
}
