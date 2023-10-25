package authz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"log/slog"

	authn "bitbucket.org/_metalogic_/authenticate"
)

type Session struct {
	Identity   *authn.Identity `json:"identity"`
	JWTToken   string          `json:"jwtToken"`
	JWTRefresh string          `json:"refreshToken"`
	Expiry     int64           `json:"expiry"` // the expiry time of the JWT in Unix seconds
}

func (s *Session) UserID() string {
	return s.Identity.UserID
}

func (s *Session) IsExpired() bool {
	return time.Unix(s.Expiry, 0).Before(time.Now())
}

func (s *Session) ExpiresAt() time.Time {
	return time.Unix(s.Expiry, 0)
}

// return just Identity in session JSON
func (s *Session) JSON() string {
	data, err := json.Marshal(s.Identity)
	if err != nil {
		data = []byte(fmt.Sprintf(`{"error": "shouldn't: failed to marshal session identity to JSON: %s"}`, err))
	}
	return string(data)
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
