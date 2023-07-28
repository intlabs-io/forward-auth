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

		// unmarshal JSON into &Login
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

// @Users TVET base-scoped endpoints
// @Summary get User User UUID
// @Description get User UUID
// @Produce json
// @Param uuid path string false "UUID of the tag"
// @Success 200 {object} tvet.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /tags/{uuid} [get]
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

// @Users TVET base-scoped
// @Summary get tags
// @Description get tags
// @Produce json
// @Param regex query string false "regex to match against tag names; uses * if none provided"
// @Success 200 {array} tvet.UserResponse
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

// @Users TVET base-scoped endpoints
// @Summary create User
// @Description create User
// @Produce json
// @Param body body tvet.User true "tag JSON object"
// @Success 200 {object} tvet.UserResponse
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

// @Users TVET base-scoped endpoints
// @Summary update Users
// @Description update Users
// @Produce json
// @Param uuid path string true "UUID of the tag"
// @Success 200 {object} tvet.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{uuid} [put]
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

// @Users TVET base-scoped endpoints
// @Summary delete User
// @Description delete User
// @Produce json
// @Param uuid path string true "UUID of the tag"
// @Success 200 {object} tvet.UserResponse
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

// @Users TVET base-scoped endpoints
// @Summary change password
// @Description change password
// @Produce json
// @Param uid path string true "UID of the user"
// @Success 200 {object} tvet.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{uid}/password [put]
func ChangePassword(svc *fauth.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]

		passwordJSON, err := client.ChangePasswordRaw(uid, r.Body)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(passwordJSON))
	}
}

// @Users TVET base-scoped endpoints
// @Summary set password
// @Description set password
// @Produce json
// @Param uid path string true "UID of the user"
// @Success 200 {object} tvet.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{uid}/password [put]
func SetPassword(svc *fauth.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		uid := params["uid"]
		// token := params["token"]

		passwordJSON, err := client.SetPasswordRaw(uid, r.Body)
		if err != nil {
			ErrJSON(w, err)
			return
		}

		OkJSON(w, string(passwordJSON))
	}
}

// @Users TVET base-scoped endpoints
// @Summary recover user account
// @Description recover user account
// @Produce json
// @Param uid path string true "UID of the user"
// @Success 200 {object} tvet.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{uid}/recover [put]
func RecoverAccount(svc *fauth.Auth, client *client.Client) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		var message []byte

		// message, err := client.RecoverAccountRaw(r.Body)
		// if err != nil {
		// 	ErrJSON(w, err)
		// 	return
		// }

		MsgJSON(w, string(message))
	}
}
