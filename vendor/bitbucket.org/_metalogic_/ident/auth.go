package ident

import (
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

// AuthType defines the authorization type
type AuthType int

// Authorization types
const (
	AuthBasic  = AuthType(1)
	AuthBearer = AuthType(2)
	AuthCookie = AuthType(3)
	AuthDigest = AuthType(4)
	AuthJWT    = AuthType(5)
)

// Authorizer is the interface for authorization
// Authorize returns true if the credentials are authorized in environment
// Name returns the name derived from credentials
type Authorizer interface {
	Authorize(authType AuthType, credentials string) bool
}

// Auth type returned by a successful authentication
type Auth struct {
	Identity  Identity `json:"identity"`
	JWT       string   `json:"jwt"`
	ExpiresAt int64    `json:"expiresAt"`
}

// Credentials ...
type Credentials struct {
	JWT   string
	Token string
}

// User ...
func (c *Credentials) User(jwtKey []byte) string {
	if c.JWT == "" {
		return ""
	}

	var err error
	var id *Identity
	if id, err = checkJWT(c.JWT, jwtKey); err != nil {
		return ""
	}

	return id.User + "," + id.Username
}

// Identity represents user properties and permission
type Identity struct {
	User        string                  `json:"userGUID"`
	Username    string                  `json:"username"`
	Root        bool                    `json:"root"`
	Permissions map[string][]Permission `json:"permissions"` // maps tenantID to permissions
}

// Claims type
type Claims struct {
	Identity *Identity `json:"user"`
	jwt.StandardClaims
}

// Credentials type
// type Credentials struct {
// 	Password string `json:"password"`
// 	Username string `json:"username"`
// }

// Role represents a named set of permissions for a tenant
type Role struct {
	Role       string       `json:"guid"`
	TenantID   string       `json:"tenantID"`
	Permission []Permission `json:"perms"`
}

// Permission represents the allowed actions on a category
type Permission struct {
	Category string   `json:"category"`
	Action   []string `json:"action"`
}

// UserPermissions defines the permissions of a user for an tenant
type UserPermissions struct {
	TenantID    string                `json:"tenantID"`
	Permissions []CategoryPermissions `json:"perms"`
}

// CategoryPermissions type
type CategoryPermissions struct {
	Category string   `json:"category"`
	Action   []string `json:"actions"`
}

func checkJWT(tknStr string, jwtKey []byte) (identity *Identity, err error) {

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
