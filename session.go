package fauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"log/slog"

	authn "bitbucket.org/_metalogic_/authenticate"
)

type session struct {
	identity     *authn.Identity
	uid          string // the uid of the session user
	jwtToken     string
	refreshToken string
	expiry       int64 // the expiry time in Unix seconds of the JWT
}

func (s session) UID() string {
	return s.uid
}

func (s session) Identity() *authn.Identity {
	return s.identity
}

func (s *session) JWT() string {
	return s.jwtToken
}

func (s *session) RefreshJWT() string {
	return s.refreshToken
}

func (s *session) IsExpired() bool {
	return time.Unix(s.expiry, 0).Before(time.Now())
}

func (s *session) ExpiresAt() time.Time {
	return time.Unix(s.expiry, 0)
}

func getSessionID(header http.Header, sessionMode, sessionName string) (id string, err error) {

	slog.Debug(fmt.Sprintf("getting session ID by %s mode, name %s", sessionMode, sessionName))

	switch strings.ToLower(sessionMode) {
	case "cookie":
		// Get the value of the "Cookie" header from the http.Header object
		cookieHeader := header.Get("Cookie")

		// Parse the cookie header string manually
		cookies := []*http.Cookie{}
		if cookieHeader != "" {
			cookieStrings := strings.Split(cookieHeader, ";")
			for _, cookieStr := range cookieStrings {
				cookieParts := strings.Split(strings.TrimSpace(cookieStr), "=")
				if len(cookieParts) == 2 {
					cookies = append(cookies, &http.Cookie{Name: cookieParts[0], Value: cookieParts[1]})
				}
			}
		}

		// Find the cookie you're interested in by its name
		for _, cookie := range cookies {
			if cookie.Name == sessionName {
				return cookie.Value, nil
			}
		}
		return id, fmt.Errorf("cookie '%s' not found in request header", sessionName)

	case "header":
		id = header.Get(sessionName)
		if id == "" {
			return id, fmt.Errorf("session header '%s' not found in request", sessionName)
		}
		return id, nil
	default:
		return id, fmt.Errorf("invalid session mode %s", sessionMode)
	}
}
