package server

//lint:file-ignore ST1001 dot import avoids package prefix in reference

import (
	"net/http"
)

func Options() func(w http.ResponseWriter, r *http.Request, params map[string]string) {

	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.WriteHeader(http.StatusOK)
		w.Write(ok)
	}
}
