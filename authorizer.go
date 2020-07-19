package fauth

import (
	"fmt"

	"bitbucket.org/_metalogic_/log"
	jwt "github.com/dgrijalva/jwt-go"
)

const (
	// ANY wildcard category matches any individual category (eg ADM, FEE, INST, etc)
	ANY = "ANY"
	// ALL wildcard action matches any of GET, PUT, POST, DELETE
	ALL = "ALL"
)

// Action constants as defined in database table [auth].[ACTIONS]
// HTTP methods are mapped to an action
const (
	CREATE = "CREATE"
	READ   = "READ"
	UPDATE = "UPDATE"
	DELETE = "DELETE"
)

// Auth type implements the Authorizer interface
type Auth struct {
	jwtKey []byte
	tokens map[string]string
}

// Bearer is required to satisfy the Authorizer interface required by the treemux handlers;
// it first checks for institution bearer token and if found returns the EPBCID of the institution owning the token
// if no institution token is found it checks application tokens and if found returns the application code associated with the token;
// if neither institution nor application token is found returns empty string
// institution tokens are checked first since they provide full tenant root access for all API requests
func (auth *Auth) Bearer(token string) bool {
	_, ok := auth.tokens[token]
	return ok
}

// User is required to satisfy the Authorizer interface required by the treemux handlers
func (auth *Auth) User(jwt string) string {
	if jwt == "" {
		return ""
	}

	var err error
	var identity *Identity
	if identity, err = checkJWT(auth.jwtKey, jwt); err != nil {
		return ""
	}

	return identity.User + "," + identity.Username
}

// Authorize is required to satisfy the Authorizer interface required by the treemux handlers
func (auth *Auth) Authorize(jwt, tenantID, category, action string) bool {
	// from this point all requests MUST have a valid JWT
	if jwt == "" {
		return false
	}

	var err error
	var identity *Identity
	if identity, err = checkJWT(auth.jwtKey, jwt); err != nil {
		log.Errorf("JWT found in request is invalid: %s", err)
		// return 401, "JWT found in request is invalid", xUser, nil
		return false
	}

	log.Debugf("identity found in JWT: %s", identity)

	if identity.Root {
		return true
	}
	for _, role := range identity.UserPermissions {
		if role.TenantID == tenantID {
			for _, perm := range role.Permissions {
				if perm.Category == ANY || perm.Category == category {
					for _, a := range perm.Action {
						if a == ALL || a == action {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// Identity type
type Identity struct {
	User            string           `json:"userGUID"`
	Username        string           `json:"username"`
	Root            bool             `json:"root"`
	UserPermissions []UserPermission `json:"userPerms"`
}

func (ident *Identity) String() string {
	return ident.Username
}

// UserPermission defines the permissions of a user for a tenant
type UserPermission struct {
	TenantID    string                `json:"tenantID"`
	Permissions []CategoryPermissions `json:"perms"`
}

// CategoryPermissions type
type CategoryPermissions struct {
	Category string   `json:"category"`
	Action   []string `json:"actions"`
}

// Claims type
type Claims struct {
	Identity *Identity `json:"identity"`
	jwt.StandardClaims
}

func checkJWT(jwtKey []byte, tknStr string) (identity *Identity, err error) {

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (that is expired according to the expiry time set at sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return identity, err
	}

	if !tkn.Valid {
		return identity, fmt.Errorf("JWT token in request is expired")
	}
	return claims.Identity, nil
}

// Action returns an action from an HTTP method
func Action(method string) string {
	switch method {
	case "GET":
		return READ
	case "POST":
		return CREATE
	case "PUT":
		return UPDATE
	case "DELETE":
		return DELETE
	default:
		return "UNDEFINED"
	}
}
