package server

//lint:file-ignore ST1001 dot import avoids package prefix in reference

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"bitbucket.org/_metalogic_/access-apis/client"
	authz "bitbucket.org/_metalogic_/authorize"
	"bitbucket.org/_metalogic_/config"
	. "bitbucket.org/_metalogic_/glib/http"
	"bitbucket.org/_metalogic_/log"
)

// @Tags Session endpoints
// @Summary executes a user login against the access-api
// @Description executes a user login against the access-api
// @ID login
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Login(svc *authz.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		token := authz.Bearer(r)
		if token == "" {
			ErrJSON(w, NewBadRequestError("login requires a valid application bearer token"))
			return
		}

		decoder := json.NewDecoder(r.Body)

		type Login struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		login := &Login{}

		// unmarshal JSON into &Login
		err := decoder.Decode(login)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		c, err := client.New(accessRootURL, accessTenantID, accessAPIKey, true, slog.Default())
		if err != nil {
			ErrJSON(w, NewServerError("new access-apis client failed: "+err.Error()))
			return
		}

		auth, err := c.Login(login.Email, login.Password)
		if err != nil {
			ErrJSON(w, NewUnauthorizedError(fmt.Sprintf("user login failed for %s: ", login.Email)))
			return
		}

		identity, err := svc.JWTIdentity(auth.JWT.JWTToken)
		if err != nil {
			ErrJSON(w, NewServerError("failed to parse identity from login response: "+err.Error()))
			return
		}

		data, err := json.Marshal(identity)
		if err != nil {
			ErrJSON(w, NewServerError("shouldn't: failed to marshal identity: "+err.Error()))
			return
		}

		sessionID, expiresAt := svc.CreateSession(token, auth.JWT, false)

		setSessionID(w, sessionMode, sessionName, sessionID, expiresAt)

		log.Debugf("response headers: %+v", w.Header())

		OkJSON(w, string(data))
	}
}

// @Tags Session endpoints
// @Summary executes a logout for the attached session token
// @Description executes a logout for the attached session token
// @ID logout
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Logout(svc *authz.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		token := authz.Bearer(r)
		if token == "" {
			ErrJSON(w, NewBadRequestError("logout requires a valid application bearer token"))
			return
		}

		if id, err := invalidateSessionID(w, r, sessionMode, sessionName); err != nil {
			ErrJSON(w, fmt.Errorf("error logging out session id %s: %s", id, err))
			return
		} else {
			svc.DeleteSession(token, id)
			MsgJSON(w, fmt.Sprintf("logged out session with id %s", id))
		}
	}
}

// @Tags Session endpoints
// @Summary executes a refresh for the attached session token
// @Description executes a refresh for the attached session token by doing
// @Description a refresh request against the access-apis with the session refreshToken
// @ID logout
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Refresh(svc *authz.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		token := authz.Bearer(r)
		if token == "" {
			ErrJSON(w, NewBadRequestError("refresh requires a valid application bearer token"))
			return
		}

		id, err := sessionID(r, sessionMode, sessionName)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		sess, err := svc.Session(token, id)
		if err != nil {
			ErrJSON(w, NewBadRequestError(fmt.Sprintf("session id '%s' not found", id)))
			return
		}

		if sess.IsExpired() {
			ErrJSON(w, NewUnauthorizedError("session is expired"))
			return
		}

		c, err := client.New(accessRootURL, accessTenantID, accessAPIKey, true, slog.Default())
		if err != nil {
			ErrJSON(w, NewServerError("failed to create access-apis client: "+err.Error()))
			return
		}
		auth, err := c.Refresh(sess.UserID(), sess.JWTRefresh)
		if err != nil {
			ErrJSON(w, NewUnauthorizedError(fmt.Sprintf("refresh failed for UID %s", sess.UserID())))
			return
		}

		identity, err := svc.JWTIdentity(auth.JWT.JWTToken)
		if err != nil {
			ErrJSON(w, NewServerError("failed to parse identity from login response: "+err.Error()))
			return
		}

		if identity.UserID != sess.UserID() {
			ErrJSON(w, NewServerError("shouldn't: user in JWT disagrees with user in session "+err.Error()))
			return
		}

		data, err := json.Marshal(identity)
		if err != nil {
			ErrJSON(w, NewServerError("shouldn't: failed to marshal identity: "+err.Error()))
			return
		}

		expiresAt := svc.UpdateSession(id, token, auth.JWT)

		setSessionID(w, sessionMode, sessionName, id, expiresAt)

		OkJSON(w, string(data))
	}
}

// @Tags Session endpoints
// @Summary returns a JSON array of active applications sessions
// @Description returns a JSON array of active applications sessions
// @ID sessions
// @Produce json
// @Success 200 {array} string
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Sessions(svc *authz.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		token := authz.Bearer(r)
		if token == "" {
			ErrJSON(w, NewBadRequestError("sessions requires a valid application bearer token"))
			return
		}

		OkJSON(w, svc.Sessions(token))
	}
}

// @Tags Session endpoints
// @Summary get session for a given session ID
// @Description get session for a give session ID
// @ID session
// @Produce json
// @Success 200 {array} types.Session
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// TODO return session details (should we do this?)
func Session(svc *authz.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		token := authz.Bearer(r)
		if token == "" {
			ErrJSON(w, NewBadRequestError("refresh session a valid application bearer token"))
			return
		}

		sid := params["sid"]
		session, err := svc.Session(token, sid)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		// TODO allow query param for getting expired sessions

		if session.IsExpired() {
			ErrJSON(w, NewBadRequestError("session is expired"))
			return
		}

		// set session cookie
		setSessionID(w, sessionMode, sessionName, sid, session.ExpiresAt())

		log.Debugf("response headers: %+v", w.Header())

		// return session identity JSON in respons
		OkJSON(w, session.JSON())

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
func Blocked(auth *authz.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
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
func Block(svc *authz.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
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
func Unblock(svc *authz.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
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

func setResetToken(w http.ResponseWriter, sessionMode, sessionName, sessionID string, expiresAt time.Time) (err error) {

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

// @Tags User endpoints
// @Summary change password
// @Description change password
// @Produce json
// @Param uid path string true "UID of the user"
// @Success 200 {object} authz.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{uid}/password [put]
func ChangePassword(svc *authz.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]

		err := client.ChangePasswordRaw(uid, r.Body)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		NoContent(w)
	}
}

// @Tags User endpoints
// @Summary set password
// @Description set password
// @Produce json
// @Param uid path string true "UID of the user"
// @Success 200 {object} authz.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{uid}/password [put]
func SetPassword(svc *authz.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]

		err := client.SetPasswordRaw(uid, r.Body)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		NoContent(w)
	}
}

// @Tags User endpoints
// @Summary initiate password reset
// @Description initiate password reset
// @Produce json
// @Success 200 {object} authz.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /password-reset [post]
// { "email": "user account email"}
func StartPasswordReset(svc *authz.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		auth, err := client.StartPasswordResetRaw(r.Body)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		identity, err := svc.JWTIdentity(auth.JWT.JWTToken)
		if err != nil {
			ErrJSON(w, NewServerError("failed to parse identity from JWT"))
			return
		}

		token := authz.Bearer(r)

		id, expiresAt := svc.CreateSession(token, auth.JWT, true)

		// id is a 6 digit string emailed to the user

		if err = sendEmail(identity.Email, "Password Reset Code", fmt.Sprintf("Reset Code: %s expiring at %s", id, expiresAt)); err != nil {
			ErrJSON(w, err)
			return
		}

		type resetResponse struct {
			UID   string `json:"uid"`
			Email string `json:"email"`
			// Expiry time.Time `json:"expiry"`
		}

		reset := &resetResponse{
			UID:   identity.UserID,
			Email: identity.Email,
			// Expiry: *ident.ExpiresAt,
		}

		resetJSON, err := json.Marshal(reset)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(resetJSON))
	}
}

// @Tags User endpoints
// @Summary recover user account
// @Description recover user account
// @Produce json
// @Param uid path string true "UID of the user"
// @Success 200 {object} authz.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{uid}/password-reset [put]
func ResetPassword(svc *authz.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]

		var message []byte

		message, err := client.ResetPasswordRaw(uid, r.Body)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		MsgJSON(w, string(message))
	}
}
