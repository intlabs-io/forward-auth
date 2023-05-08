package server

//lint:file-ignore ST1001 dot import avoids package prefix in reference

import (
	"net/http"

	fauth "bitbucket.org/_metalogic_/forward-auth"
)

func Options(auth *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {

	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.WriteHeader(http.StatusOK)
		w.Write(ok)
	}
}
