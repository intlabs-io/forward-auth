package auth

import (
	"net/http"

	"bitbucket.org/_metalogic_/log"
)

/*
 * Authorization handlers
 */

// AllowHandler always allows access
func AllowHandler(method, path string, paramMap map[string][]string, header http.Header) (status int, message string) {
	log.Debugf("allowing %s %s with params %v", method, path, paramMap)
	return http.StatusOK, http.StatusText(http.StatusOK)
}

// DenyHandler always denies access
func DenyHandler(method, path string, paramMap map[string][]string, header http.Header) (status int, message string) {
	log.Debugf("denying %s %s with params %v", method, path, paramMap)
	return http.StatusForbidden, http.StatusText(http.StatusForbidden)
}

// OptionsHandler is called for all OPTION requests regardless of path
func OptionsHandler(method, path string, paramMap map[string][]string, header http.Header) (status int, message string) {
	log.Debugf("calling options handler for path %s", path)
	return http.StatusNoContent, ""
}
