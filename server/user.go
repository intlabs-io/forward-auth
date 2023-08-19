package server

//lint:file-ignore ST1001 dot import avoids package prefix in reference

import (
	"net/http"

	"bitbucket.org/_metalogic_/access-apis/client"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http"
	"bitbucket.org/_metalogic_/log"
)

// @Tags User endpoints
// @Summary get User User UUID
// @Description get User UUID
// @Produce json
// @Param uuid path string false "UUID of the tag"
// @Success 200 {object} fauth.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{uuid} [get]
func User(svc *fauth.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]
		userResponse, err := client.GetUserRaw(uid)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(userResponse))
	}
}

// @Tags User endpoints
// @Summary get users
// @Description get users
// @Produce json
// @Param regex query string false "regex to match against tag names; uses * if none provided"
// @Success 200 {array} fauth.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users [get]
func Users(svc *fauth.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		usersResponse, err := client.GetUsersRaw()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(usersResponse))
	}
}

// @Tags User endpoints
// @Summary create User
// @Description create User
// @Produce json
// @Param body body fauth.User true "tag JSON object"
// @Success 200 {object} fauth.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users [post]
func CreateUser(svc *fauth.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		maxsize := getMaxUploadSize()

		// Limit maximum body size of POST
		r.Body = http.MaxBytesReader(w, r.Body, maxsize)

		log.Debugf("Body: %v", r.Body)

		userResponse, err := client.CreateUserRaw(r.Body)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(userResponse))
	}
}

// @Tags User endpoints
// @Summary update Users
// @Description update Users
// @Produce json
// @Param uuid path string true "UUID of the tag"
// @Success 200 {object} fauth.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{uid} [put]
func UpdateUser(svc *fauth.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]

		log.Debugf("Body: %v", r.Body)

		userJSON, err := client.UpdateUserRaw(uid, r.Body)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(userJSON))
	}
}

// @Tags User endpoints
// @Summary delete User
// @Description delete User
// @Produce json
// @Param uuid path string true "UUID of the tag"
// @Success 200 {object} fauth.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{uuid} [delete]
func DeleteUser(svc *fauth.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]

		deleteJSON, err := client.DeleteUserRaw(uid)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(deleteJSON))
	}
}
