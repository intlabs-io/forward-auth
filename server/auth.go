package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http" // dot import fo avoid package prefix in reference (shutup lint)
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
		case 401: // TODO send WWW-Authenticate in response header
			ErrJSON(w, NewUnauthorizedError(message))
		case 403:
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

// @Tags Auth endpoints
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
		tree := ""
		MsgJSON(w, tree)
	}
}

// @Tags Auth endpoints
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

// @Tags Auth endpoints
// @Summary forces an auth update from a store
// @Description forces an auth update from a store (invoked via broadcast from /reload)
// @ID post-update
// @Produce  json
// @Success 200 {string} ok
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /forward-auth/v1/auth [get]
func Update(auth *fauth.Auth, store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		// get access control system from the store
		acs, err := store.Load()
		if err != nil {
			ErrJSON(w, err)
			return
		}
		// update auth
		err = auth.UpdateFunc()(acs)
		if err != nil {
			ErrJSON(w, err)
			return
		}
		MsgJSON(w, "access rules update succeeded")
	}
}
