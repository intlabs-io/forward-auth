package server

//lint:file-ignore ST1001 dot import avoids package prefix in reference

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"bitbucket.org/_metalogic_/access-apis/client"
	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http"
	"bitbucket.org/_metalogic_/log"
)

// @Tags User endpoints
// @Summary executes a user login against the access-api
// @Description executes a user login against the access-api
// @ID login
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Login(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		decoder := json.NewDecoder(r.Body)

		type Login struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		login := &Login{}

		// unmarshal JSON into &login
		err := decoder.Decode(login)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		c, err := client.New(accessRootURL, accessTenantID, accessAPIKey, true)
		if err != nil {
			ErrJSON(w, NewServerError("new access-apis client failed: "+err.Error()))
			return
		}

		a, err := c.Login(login.Email, login.Password)
		if err != nil {
			ErrJSON(w, NewUnauthorizedError(fmt.Sprintf("user login failed for %s: ", login.Email)))
			return
		}

		secure := config.IfGetBool("SESSION_SECURE_COOKIE", true)
		httpOnly := config.IfGetBool("SESSION_HTTP_ONLY", true)

		id := svc.CreateSession(a)
		cookie := http.Cookie{
			Name:     cookieName,
			Value:    id,
			Domain:   cookieDomain,
			Secure:   secure, // TODO this should come from environment
			Expires:  time.Unix(a.ExpiresAt, 0),
			HttpOnly: httpOnly,
		}

		log.Debugf("setting session cookie: %+v", cookie)

		// set session cookie in response and return user identity JSON
		http.SetCookie(w, &cookie)

		data, err := json.Marshal(a.Identity)
		if err != nil {
			ErrJSON(w, NewServerError("failed to parse login response as Auth.Identity: "+err.Error()))
			return
		}

		OkJSON(w, string(data))
	}
}

// @Tags User endpoints
// @Summary executes a logout for the attached session cookie
// @Description executes a logout for the attached session cookie
// @ID logout
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Logout(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		cookie, err := r.Cookie(cookieName)

		var id string
		if err == nil {
			id = cookie.Value
			svc.DeleteSession(id)
		}

		expired := &http.Cookie{
			Name:     cookieName,
			Domain:   cookieDomain,
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
		}
		// set expired session cookie in response and return user identity JSON
		http.SetCookie(w, expired)
		MsgJSON(w, "logged out session "+id)
	}
}

// @Tags User endpoints
// @Summary executes a refresh for the attached session cookie
// @Description executes a refresh for the attached session cookie by doing
// @Description a refresh request against the access-apis with the session refreshToken
// @ID logout
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Refresh(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		cookie, err := r.Cookie(cookieName)

		if err != nil {
			ErrJSON(w, NewBadRequestError("session cookie not found in request"))
			return
		}

		id := cookie.Value

		sess, err := svc.Session(id)
		if err != nil {
			ErrJSON(w, NewBadRequestError("session not found"))
			return
		}

		if sess.IsExpired() {
			ErrJSON(w, NewUnauthorizedError("session is expired"))
			return
		}

		c, err := client.New(accessRootURL, accessTenantID, accessAPIKey, true)
		if err != nil {
			ErrJSON(w, NewServerError("new access-apis client failed: "+err.Error()))
			return
		}
		a, err := c.Refresh(sess.UID(), sess.RefreshJWT())
		if err != nil {
			ErrJSON(w, NewUnauthorizedError(fmt.Sprintf("refresh failed for UID %s: ", sess.UID())))
			return
		}

		svc.UpdateSession(id, a)

		// set updated cookie in response and return user identity JSON
		cookie = &http.Cookie{
			Name:     cookieName,
			Value:    id,
			Domain:   cookieDomain,
			Expires:  time.Unix(a.ExpiresAt, 0),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)

		data, err := json.Marshal(a.Identity)
		if err != nil {
			ErrJSON(w, NewServerError("failed to parse refresh response from access-apis as Auth.Identity: "+err.Error()))
			return
		}

		OkJSON(w, string(data))
	}
}

// @Tags User endpoints
// @Summary returns a JSON array of active session IDs
// @Description returns a JSON array of active session IDs
// @ID sessions
// @Produce json
// @Success 200 {array} string
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Sessions(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		OkJSON(w, svc.Sessions())
	}
}

// @Tags User endpoints
// @Summary adds uid to the user blocklist
// @Description adds uid to the user blocklist
// @ID block
// @Produce json
// @Success 200 {array} types.Session
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Session(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		// sid := params["sid"]

		w.Header().Set("Content-Type", "application/json")
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
// @Summary adds uid to the user blocklist
// @Description adds uid to the user blocklist
// @ID block
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Block(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		uid := params["uid"]
		svc.Block(uid)
		b := fmt.Sprintf("{ \"blocked\" : \"%s\" }", uid)
		MsgJSON(w, b)
	}
}

// @Tags User endpoints
// @Summary removes uid from the user blocklist
// @Description removes uid from the user blocklist
// @ID unblock
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Unblock(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		uid := params["uid"]
		svc.Unblock(uid)
		b := fmt.Sprintf("{ \"unblocked\" : \"%s\" }", uid)
		MsgJSON(w, b)
	}
}
