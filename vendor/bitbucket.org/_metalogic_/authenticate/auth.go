package authn

import (
	"encoding/json"
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
// type Auth struct {
// 	User      Identity `json:"identity"`
// 	JWT       string   `json:"jwt"`
// 	ExpiresAt int64    `json:"expiresAt"`
// }

// Auth type returned by a successful authentication
type Auth struct {
	JWT        string `json:"jwt"`
	JWTRefresh string `json:"jwtRefresh"`
	ExpiresAt  int64  `json:"expiresAt"`
}

func (auth *Auth) JSON() string {
	b, err := json.Marshal(auth)
	if err != nil {
		return fmt.Sprintf(`{"error": "%s"}`, err)
	}
	return string(b)
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
	if id, err = jwtIdentity(c.JWT, jwtKey); err != nil {
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

func (c *Credentials) Check(jwtKey []byte, context, action, category string) (result bool, err error) {
	if c.JWT == "" {
		return result, fmt.Errorf("cannot check empty JWT credentials")
	}

	identity, err := jwtIdentity(c.JWT, jwtKey)
	if err != nil {
		return result, fmt.Errorf("get identity failed: %s", err)
	}

	return identity.HasPermission(identity.TenantID, context, action, category), nil

}

// Claims type
type Claims struct {
	Identity *Identity `json:"user"`
	jwt.StandardClaims
}

func jwtIdentity(tknStr string, jwtKey []byte) (identity *Identity, err error) {

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
