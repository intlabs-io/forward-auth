package authz

import (
	"bitbucket.org/_metalogic_/env"
)

const (
	// ActionAll wildcard action matches any of CREATE, READ, UPDATE, DELETE, EXISTS; also used for all contexts
	ActionAll = "ALL"
)

// Action constants as defined in database table auth.ACTIONS
const (
	CREATE = "CREATE"
	READ   = "READ"
	UPDATE = "UPDATE"
	DELETE = "DELETE"
	EXISTS = "EXISTS"
)

// Authorizer is the interface for authorization
// Authorize returns true if the request should be authorized
// in environment
// TODO - should we pass authenticators in the configuration of the Authorizer
// or should the authenticator be passed as an argument to Authorize()?
type Authorizer interface {
	Authorize(r Request, env *env.Vars) bool
}

// Request encapsulates an authorization request
type Request struct {
	Action    string
	Resource  string
	Params    map[string][]string
	Body      []byte
	Signature string
}
