package http

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	fa "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	"github.com/pborman/uuid"
)

var ok = []byte("ok")

// Auth authorizes a request based on configured access control rules
func Auth(svc fa.Service, jwtHeader, traceHeader, userHeader string) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		if svc.RunMode() == "noAuth" {
			log.Warning("runMode is set to 'noAuth' - all access controls are disabled")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "ok")
			return
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

		// Request Headers
		authMode := r.Header.Get("Forward-Auth-Mode")
		authHeader := r.Header.Get("Authorization")
		host := r.Header.Get("X-Forwarded-Host")
		method := r.Header.Get("X-Forwarded-Method")
		path := r.Header.Get("X-Forwarded-Uri")
		traceID := r.Header.Get(traceHeader)

		var token string
		if authHeader != "" {
			// Get the Bearer auth token
			splitToken := strings.Split(authHeader, "Bearer ")
			if len(splitToken) == 2 {
				token = splitToken[1]
			}
		}

		log.Debugf("HTTP Request Headers: %s", headers(r))

		jwt := r.Header.Get(jwtHeader)

		status, message, user, err := svc.Auth(host, method, path, token, jwt)

		if err != nil {
			errJSON(w, err)
			return
		}

		if authMode == "testing" {
			log.Warning("authMode testing is enabled by Forward-Auth-Mode header - no requests are being forwarded")
			tstJSON(w, status, message, user)
			return
		}

		if traceID == "" {
			traceID = uuid.New()
			log.Debugf("setting %s in header: %s", traceHeader, traceID)
		} else {
			log.Debugf("found %sin header: %s", traceHeader, traceID)
		}

		switch status {
		case 401: // TODO send WWW-Authenticate in response header
			errJSON(w, fa.NewUnauthorizedError(message))
		case 403:
			errJSON(w, fa.NewForbiddenError(message))
		case 200:
			if user != "" {
				u := strings.Split(user, ",")
				if len(u) != 2 {
					log.Errorf("invalid user returned from checkAuth: %s", user)
					return
				}
				// if epbcUserID != "" && epbcUserID != u[0] { // Epbc-User header must agree with user in JWT
				// 	errJSON(w, fa.NewUnauthorizedError(message))
				// }

				// log.Debugf("Epbc-User header = %s, UserGUID from JWT = %s", u[0])
				log.Debugf("UserID from JWT = %s", u[0])

				w.Header().Add(userHeader, u[0])
			}
			w.Write(ok)
		}
	}
}
