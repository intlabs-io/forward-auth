package server

//lint:file-ignore ST1001 dot import avoids package prefix in reference

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http"
	"bitbucket.org/_metalogic_/log"
	"github.com/pborman/uuid"
)

var ok = []byte("ok")

// @Tags Auth endpoints
// @Summary authorizes a request based on configured access control rules
// @Description authorizes a request based on configured access control rules;
// @Description jwtHeader, traceHeader and userHeader are added to the forwarded request headers
// @ID get-auth
// @Produce  json
// @Success 200 {string} ok
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /forward-auth/v1/auth [get]
func Auth(auth *fauth.Auth, userHeader, traceHeader string) func(w http.ResponseWriter, r *http.Request, params map[string]string) {

	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		if auth.RunMode() == "noAuth" {
			log.Warning("runMode is set to 'noAuth' - all access controls are disabled")
			w.WriteHeader(http.StatusOK)
			w.Write(ok)
			return
		}

		testing := (r.Header.Get("Forward-Auth-Mode") == "testing")
		if testing {
			log.Warning("authMode testing is enabled by Forward-Auth-Mode header - no requests are being forwarded")
		}

		if log.Loggable(log.DebugLevel) {
			data, err := httputil.DumpRequest(r, false)
			if err != nil {
				ErrJSON(w, NewUnauthorizedError("authorization failed to unpack request"))
				return
			}
			raw := strconv.Quote(strings.ReplaceAll(strings.ReplaceAll(string(data), "\r", ""), "\n", "; "))
			log.Debugf("dump raw HTTP request: %s", raw[1:len(raw)-1])
		}

		// pass or create traceID and add to request header
		traceID := r.Header.Get(traceHeader)
		if traceID == "" {
			traceID = uuid.New()
			log.Debugf("setting %s in header: %s", traceHeader, traceID)
			w.Header().Add(traceHeader, traceID)
		} else {
			log.Debugf("found %s in header: %s", traceHeader, traceID)
		}

		// forwarded request headers are used for authorization decisions
		host := r.Header.Get("X-Forwarded-Host")
		method := r.Header.Get("X-Forwarded-Method")
		path := r.Header.Get("X-Forwarded-Uri")

		// allow all OPTIONS requests regardless of path;
		// we need this to avoid going mad allowing CORS preflight checks
		if method == http.MethodOptions {
			log.Debug("allowing OPTIONS request")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// override checks on the request when a root bearer token is found
		// enabling root override avoids repeated use of "bearer('ROOT_KEY')" in check expressions
		if auth.RootOverride() && rootAuth(r, auth) {
			log.Debug("allowing request with root bearer token")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// check for host overrides
		if auth.Override(host) == "allow" {
			if testing {
				tstJSON(w, http.StatusOK, "allow override for host "+host)
			} else {
				OkJSON(w, "allow override for host "+host)
			}
			log.Debug("allow override for host " + host)
			return
		} else if auth.Override(host) == "deny" {
			if testing {
				tstJSON(w, http.StatusForbidden, "deny override for host "+host)
			} else {
				ErrJSON(w, NewForbiddenError("deny override for host "+host))
			}
			log.Debug("deny override for host " + host)
			return
		}

		mux, err := auth.Muxer(host)
		if err != nil { // shouldn't happen
			ErrJSON(w, NewForbiddenError(err.Error()))
			return
		}

		// TODO return user - username is always empty in this call ??
		status, message, username := mux.Check(method, path, r.Header)

		if testing {
			tstJSON(w, status, message)
			return
		}

		switch status {
		case 401: // upstream should handle login
			ErrJSON(w, NewUnauthorizedError(message))
		case 403:
			ErrJSON(w, NewForbiddenError(message))
		case 404: // always deny on not found
			ErrJSON(w, NewForbiddenError(message))
		case 200:
			if username != "" {
				log.Debugf("Adding HTTP header %s %s", userHeader, username)
				w.Header().Add(userHeader, username)
			}
			w.Write(ok)
		}
	}
}

// @Tags Auth endpoints
// @Summary TODO: returns a text representation of the access tree
// @Description TODO: returns a text representation of the access tree
// @ID get-tree
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func Tree(auth *fauth.Auth) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		data, err := json.MarshalIndent(auth, "", "  ")
		if err != nil {
			ErrJSON(w, err)
		}
		MsgJSON(w, string(data))
	}
}

// @Tags Auth endpoints
// @Summary forces an auth update from a store
// @Description forces an auth update from a store (invoked via broadcast from /reload)
// @ID update-auth
// @Produce  json
// @Success 200 {string} ok
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /forward-auth/v1/auth [put]
func Update(auth *fauth.Auth, store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		// get access control system from the store
		acs, err := store.Load()
		if err != nil {
			ErrJSON(w, err)
			return
		}
		// update access
		err = auth.UpdateFunc()(acs)
		if err != nil {
			ErrJSON(w, err)
			return
		}
		MsgJSON(w, "access system update succeeded")
	}
}

func rootAuth(r *http.Request, auth *fauth.Auth) bool {
	authHeader := r.Header.Get("Authorization")

	var token string
	if authHeader != "" {
		// Get the Bearer auth token
		splitToken := strings.Split(authHeader, "Bearer ")
		if len(splitToken) == 2 {
			token = splitToken[1]
		}
	}

	// allow all requests with ROOT_KEY
	return auth.CheckBearerAuth(token, []string{"ROOT_KEY"}...)
}
