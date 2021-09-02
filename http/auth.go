package http

import (
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

// jwtHeader, traceHeader and userHeader are added to the forwarded request headers
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
// @Router /forward-auth/v1/stats [get]
func Auth(svc fauth.Service, userHeader, traceHeader string) func(w http.ResponseWriter, r *http.Request, params map[string]string) {

	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		if svc.RunMode() == "noAuth" {
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
		if svc.Override(host) == "allow" {
			if testing {
				tstJSON(w, http.StatusOK, "allow override for host "+host)
			} else {
				OkJSON(w, "allow override for host "+host)
			}
			log.Debug("allow override for host " + host)
			return
		} else if svc.Override(host) == "deny" {
			if testing {
				tstJSON(w, http.StatusForbidden, "deny override for host "+host)
			} else {
				ErrJSON(w, NewForbiddenError("deny override for host "+host))
			}
			log.Debug("deny override for host " + host)
			return
		}

		mux, err := svc.Muxer(host)
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

// HostChecks returns a handler for returning the configured access control rules
func HostChecks(svc fauth.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		hostChecks, err := svc.HostChecks()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}
