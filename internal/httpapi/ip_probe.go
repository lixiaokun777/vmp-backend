package httpapi

import (
	"encoding/json"
	"net/http"
)

func (a *API) probeIPAddress(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Release bool `json:"release_if_free"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input) != nil {
		writeError(w, 400, "IP复核参数无效")
		return
	}
	user, _ := userFromRequest(r)
	result, err := a.Service.ProbeIPAddress(r.Context(), user.Username, r.PathValue("id"), input.Release)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (a *API) probeQuarantinedNetwork(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Release bool `json:"release_if_free"`
		Limit   *int `json:"limit"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input) != nil {
		writeError(w, 400, "批量复核参数无效")
		return
	}
	limit := 32
	if input.Limit != nil {
		limit = *input.Limit
	}
	user, _ := userFromRequest(r)
	result, err := a.Service.ProbeQuarantinedNetwork(r.Context(), user.Username, r.PathValue("id"), input.Release, limit)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}
