package server

//lint:file-ignore ST1001 dot import avoids package prefix in reference

import (
	"net/http"

	"bitbucket.org/_metalogic_/access-apis/client"
	authz "bitbucket.org/_metalogic_/authorize"
	. "bitbucket.org/_metalogic_/glib/http"
	"bitbucket.org/_metalogic_/log"
)

// @Tags Context endpoints
// @Summary get Context UUID
// @Description get Context UUID
// @Produce json
// @Param uuid path string false "UUID of the tag"
// @Success 200 {object} fauth.ContextResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /contexts/{uuid} [get]
func Context(svc *authz.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]
		contextResponse, err := client.GetContextRaw(uid)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(contextResponse))
	}
}

// @Tags Context endpoints
// @Summary get contexts
// @Description get contexts
// @Produce json
// @Param regex query string false "regex to match against tag names; uses * if none provided"
// @Success 200 {array} fauth.ContextResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /contexts [get]
func Contexts(svc *authz.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		contextsResponse, err := client.GetContextsRaw()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(contextsResponse))
	}
}

// @Tags Context endpoints
// @Summary create Context
// @Description create Context
// @Produce json
// @Param body body fauth.Context true "tag JSON object"
// @Success 200 {object} fauth.ContextResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /contexts [post]
func CreateContext(svc *authz.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		maxsize := getMaxUploadSize()

		// Limit maximum body size of POST
		r.Body = http.MaxBytesReader(w, r.Body, maxsize)

		log.Debugf("Body: %v", r.Body)

		contextResponse, err := client.CreateContextRaw(r.Body)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(contextResponse))
	}
}

// @Tags Context endpoints
// @Summary update Contexts
// @Description update Contexts
// @Produce json
// @Param uuid path string true "UUID of the tag"
// @Success 200 {object} fauth.ContextResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /contexts/{uid} [put]
func UpdateContext(svc *authz.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]

		log.Debugf("Body: %v", r.Body)

		contextJSON, err := client.UpdateContextRaw(uid, r.Body)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(contextJSON))
	}
}

// @Tags Context endpoints
// @Summary delete Context
// @Description delete Context
// @Produce json
// @Param uuid path string true "UUID of the tag"
// @Success 200 {object} fauth.ContextResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /contexts/{uuid} [delete]
func DeleteContext(svc *authz.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]

		deleteJSON, err := client.DeleteContextRaw(uid)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(deleteJSON))
	}
}
