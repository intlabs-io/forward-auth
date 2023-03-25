package server

//lint:file-ignore ST1001 dot import avoids package prefix in reference

import (
	"fmt"
	"net/http"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http"
)

// @Tags User endpoints
// @Summary adds userGUID to the user blocklist
// @Description adds userGUID to the user blocklist
// @ID block
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Login(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		userGUID := params["userGUID"]
		svc.Block(userGUID)
		b := fmt.Sprintf("{ \"blocked\" : \"%s\" }", userGUID)
		MsgJSON(w, b)
	}
}

// @Tags User endpoints
// @Summary returns an array of blocked users
// @Description returns an array of blocked users
// @ID get-blocked
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Blocked(auth *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		msgJSONList(w, auth.Blocked())
	}
}

// @Tags User endpoints
// @Summary adds userGUID to the user blocklist
// @Description adds userGUID to the user blocklist
// @ID block
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Block(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		userGUID := params["userGUID"]
		svc.Block(userGUID)
		b := fmt.Sprintf("{ \"blocked\" : \"%s\" }", userGUID)
		MsgJSON(w, b)
	}
}

// @Tags User endpoints
// @Summary removes userGUID from the user blocklist
// @Description removes userGUID from the user blocklist
// @ID unblock
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Unblock(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		userGUID := params["userGUID"]
		svc.Unblock(userGUID)
		b := fmt.Sprintf("{ \"unblocked\" : \"%s\" }", userGUID)
		MsgJSON(w, b)
	}
}
