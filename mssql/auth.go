package mssql

import (
	"net/http"

	fa "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/ident"
)

// Auth returns an authorization decision for host, method and path
func (svc *Service) Auth(host, method, path, token, jwt string) (status int, message, user string, err error) {

	checker := svc.Checks(host)
	if checker == nil { // shouldn't happen
		return http.StatusForbidden, "unauthorized: no checks defined for " + host, user, nil
	}

	// initialize Identity for this check
	id := &fa.Auth{BearerToken: token, JWT: jwt}
	status = checker.Check(method, path, ident.Authorizer(id))

	user = ident.Authorizer(id).User()

	if status == http.StatusOK || status == http.StatusCreated {
		return http.StatusOK, "authorized", user, nil
	}

	return status, "unauthorized", user, nil
}

// Block adds userID to the user block access list
// TODO protect with mutex
func (svc *Service) Block(userID string) {
	svc.blocks[userID] = true

}

// Unblock removes userID from the user block access list
// TODO protect with mutex
func (svc *Service) Unblock(userID string) {
	delete(svc.blocks, userID)
}

// Blocked returns the user block access list
func (svc *Service) Blocked() []string {
	var blocks []string
	for b := range svc.blocks {
		blocks = append(blocks, b)
	}
	return blocks
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
