package mssql

import (
	"net/http"

	"bitbucket.org/_metalogic_/ident"
	_ "github.com/denisenkom/go-mssqldb"
)

// Authorize returns an authorization decision for host, method and path with given credentials
func (svc *Service) Authorize(host, method, path string, credentials *ident.Credentials) (status int, message string, err error) {

	return http.StatusForbidden, message, nil
}

// RunMode returns the current value of RunMode
func (svc *Service) RunMode() string {
	svc.lock.Lock()
	defer svc.lock.Unlock()
	return svc.runMode
}

// SetRunMode sets the value of RunMode
func (svc *Service) SetRunMode(mode string) {
	svc.lock.Lock()
	defer svc.lock.Unlock()
	svc.runMode = mode
}
