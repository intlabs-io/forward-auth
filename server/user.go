package server

//lint:file-ignore ST1001 dot import avoids package prefix in reference

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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

		data, err := json.Marshal(a.Identity)
		if err != nil {
			ErrJSON(w, NewServerError("failed to parse login response as Auth.Identity: "+err.Error()))
			return
		}

		id, expiresAt := svc.CreateSession(a)

		setSessionID(w, sessionMode, sessionName, id, expiresAt)

		log.Debugf("response headers: %+v", w.Header())

		OkJSON(w, string(data))
	}
}

// @Tags User endpoints
// @Summary executes a logout for the attached session token
// @Description executes a logout for the attached session token
// @ID logout
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Logout(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		if id, err := invalidateSessionID(w, r, sessionMode, sessionName); err != nil {
			ErrJSON(w, fmt.Errorf("error logging out session id %s: %s", id, err))
			return
		} else {
			svc.DeleteSession(id)
			MsgJSON(w, fmt.Sprintf("logged out session with id %s", id))
		}
	}
}

// @Tags User endpoints
// @Summary executes a refresh for the attached session token
// @Description executes a refresh for the attached session token by doing
// @Description a refresh request against the access-apis with the session refreshToken
// @ID logout
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Refresh(svc *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		// cookie, err := r.Cookie(sessionName)

		// if err != nil {
		// 	ErrJSON(w, NewBadRequestError(fmt.Sprintf("session cookie '%s' not found in request", sessionName)))
		// 	return
		// }

		// id := cookie.Value

		id, err := sessionID(r, sessionMode, sessionName)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		sess, err := svc.Session(id)
		if err != nil {
			ErrJSON(w, NewBadRequestError(fmt.Sprintf("session id '%s' not found", id)))
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

		data, err := json.Marshal(a.Identity)
		if err != nil {
			ErrJSON(w, NewServerError("failed to parse refresh response from access-apis as Auth.Identity: "+err.Error()))
			return
		}

		expiresAt := svc.UpdateSession(id, a)

		setSessionID(w, sessionMode, sessionName, id, expiresAt)

		// // set updated cookie in response and return user identity JSON
		// cookie = &http.Cookie{
		// 	Name:     sessionName,
		// 	Value:    id,
		// 	Domain:   cookieDomain,
		// 	Expires:  time.Unix(a.ExpiresAt, 0),
		// 	HttpOnly: true,
		// }
		// http.SetCookie(w, cookie)

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
// TODO return session details (should we do this?)
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

func sessionID(r *http.Request, sessionMode, sessionName string) (id string, err error) {
	switch strings.ToLower(sessionMode) {
	case "cookie":
		if cookie, err := r.Cookie(sessionName); err != nil {
			return id, err
		} else if cookie == nil {
			return id, fmt.Errorf("session cookie not found with name %s", sessionName)
		} else {
			return cookie.Name, nil
		}
	case "header":
		id := r.Header.Get(sessionName)
		if id == "" {
			return id, fmt.Errorf("session header not found with name %s", sessionName)
		}
		return id, nil
	default:
		return id, fmt.Errorf("invalid session mode %s", sessionMode)
	}
}

func setSessionID(w http.ResponseWriter, sessionMode, sessionName, sessionID string, expiresAt time.Time) (err error) {

	switch strings.ToLower(sessionMode) {
	case "cookie", "header":
		httpOnly := config.IfGetBool("SESSION_HTTP_ONLY_COOKIE", false)
		secure := config.IfGetBool("SESSION_SECURE_COOKIE", true)
		cookie := http.Cookie{
			Name:  sessionName,
			Value: sessionID,
			// for debugging from localhost	Domain:   cookieDomain,
			HttpOnly: httpOnly,
			Secure:   secure,
			Expires:  expiresAt,
			SameSite: http.SameSiteNoneMode,
		}

		log.Debugf("setting session cookie: %+v", cookie)

		// set session cookie in response and return user identity JSON
		http.SetCookie(w, &cookie)
		return nil
	// case "header":
	// 	cookie := http.Cookie{
	// 		Value:   sessionID,
	// 		Expires: expiresAt,
	// 	}
	// 	w.Header().Set(sessionName, cookie.String())
	// 	return nil
	default:
		return fmt.Errorf("invalid session mode: %s", sessionMode)
	}

}

func invalidateSessionID(w http.ResponseWriter, r *http.Request, sessionMode, sessionName string) (id string, err error) {

	switch strings.ToLower(sessionMode) {
	case "cookie", "header":
		httpOnly := config.IfGetBool("SESSION_HTTP_ONLY_COOKIE", false)
		secure := config.IfGetBool("SESSION_SECURE_COOKIE", true)
		cookieDomain := config.IfGetenv("SESSION_COOKIE_DOMAIN", "")

		cookie, err := r.Cookie(sessionName)

		if err == nil {
			id = cookie.Value

		}
		expired := &http.Cookie{
			Name:     sessionName,
			Domain:   cookieDomain,
			Expires:  time.Unix(0, 0),
			HttpOnly: httpOnly,
			Secure:   secure,
		}
		// set expired session cookie in response and return user identity JSON
		http.SetCookie(w, expired)
		return id, nil

	// case "header":
	// 	id := r.Header.Get(sessionName)
	// 	if id == "" {
	// 		return id, fmt.Errorf("session header not found with name %s", sessionName)
	// 	}
	// 	// set empty header
	// 	return "", nil
	default:
		return id, fmt.Errorf("invalid session mode %s", sessionMode)
	}

}
