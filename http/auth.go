package http

import (
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	fa "bitbucket.org/_metalogic_/forward-auth"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	"github.com/pborman/uuid"
)

var ok = []byte("ok")

// Auth authorizes a request based on configured access control rules;
// jwtHeader, traceHeader and userHeader are added to the forwarded request headers
func Auth(svc fa.Service, jwtHeader, traceHeader, userHeader string) func(w http.ResponseWriter, r *http.Request, params map[string]string) {

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
				errJSON(w, fa.NewUnauthorizedError("authorization failed to unpack request"))
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

		if svc.AllowHost(host) {
			if testing {
				tstJSON(w, http.StatusOK, "authorized for allow host "+host)
			} else {
				okJSON(w, "authorized for allow host "+host)
			}
			return
		}

		if svc.DenyHost(host) {
			if testing {
				tstJSON(w, http.StatusForbidden, "unauthorized for blocked host "+host)
			} else {
				errJSON(w, fa.NewForbiddenError("unauthorized for blocked host "+host))
			}
			return
		}

		// authHeader := r.Header.Get("Authorization")
		// var token string
		// if authHeader != "" {
		// 	// Get the Bearer auth token
		// 	splitToken := strings.Split(authHeader, "Bearer ")
		// 	if len(splitToken) == 2 {
		// 		token = splitToken[1]
		// 	}
		// }

		// log.Debugf("HTTP Request Headers: %s", headers(r))

		// jwt := r.Header.Get(jwtHeader)

		// credentials := &ident.Credentials{
		// 	Token: token,
		// 	JWT:   jwt,
		// }

		mux, err := svc.Checks(host)
		if err != nil { // shouldn't happen
			errJSON(w, fa.NewForbiddenError(err.Error()))
			return
		}

		// TODO return user ??
		status, message, username := mux.Check(method, path, r.Header)

		if testing {
			tstJSON(w, status, message)
			return
		}

		switch status {
		case 401: // TODO send WWW-Authenticate in response header
			errJSON(w, fa.NewUnauthorizedError(message))
		case 403:
			errJSON(w, fa.NewForbiddenError(message))
		case 200:
			w.Header().Add(userHeader, username)
			w.Write(ok)
		}
	}
}

// Rules returns a handler for returning the configured access control rules
func Rules(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		rules, err := svc.Rules()
		if err != nil {
			errJSON(w, fauth.NewServerError(err.Error()))
			return
		}
		okJSON(w, rules)
	}
}
