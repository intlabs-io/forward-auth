package authn

import (
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

// AuthType defines the authorization type
type AuthType int

// Authentication types
const (
	AuthBasic  = AuthType(1)
	AuthBearer = AuthType(2)
	AuthCookie = AuthType(3)
	AuthDigest = AuthType(4)
	AuthJWT    = AuthType(5)
)

const (
	// ANY wildcard category matches any individual category (eg FINANCE, CONTENT, IMAGE, etc)
	CategoryAny = "ANY"
	// ALL context matches any category
	ContextsAll = "ALL"
	// ALL wildcard action matches any of CREATE, READ, UPDATE, DELETE, EXISTS; also used for all contexts
	ActionAll = "ALL"
)

// Auth type returned by a successful authentication
type Auth struct {
	User      Identity `json:"identity"`
	JWT       string   `json:"jwt"`
	ExpiresAt int64    `json:"expiresAt"`
}

// Credentials ...
type Credentials struct {
	JWT   string
	Token string
}

// User ...
func (c *Credentials) User(jwtKey []byte) (username string) {
	if c.JWT == "" {
		return ""
	}

	var err error
	var id *Identity
	if id, err = checkJWT(c.JWT, jwtKey); err != nil {
		return username
	}

	if id.UserID != "" {
		username = id.UserID
	}
	if id.Name != "nil" {
		if username == "" {
			username = id.Name
		} else {
			username = username + "," + id.Name
		}
	}
	return username
}

// Claims type
type Claims struct {
	Identity *Identity `json:"user"`
	jwt.StandardClaims
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
