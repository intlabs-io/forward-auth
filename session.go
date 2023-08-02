package fauth

import (
	"fmt"
	"net/http"
	"strings"
)

func getSessionID(header http.Header, sessionMode, sessionName string) (id string, err error) {
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
