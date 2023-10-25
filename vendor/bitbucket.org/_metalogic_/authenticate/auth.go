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
	// ALL context matches any individual context
	ContextsAll = "ALL"
	// ALL wildcard action matches any individual action (eg CREATE, READ, UPDATE, DELETE, EXISTS, etc)
	ActionAll = "ALL"
)

// Auth type is returned by a successful user login workflow.
//
// JWT encapsulates the user credentials; they are present in the
// Auth returned by a successful user/password login step of a user
// who has not enabled two-factor authentication (*Valid2FA will be nil).
// If the user has enabled two-factor authentication, the response from a
// successful user/password login step will return an Auth in the response with
// *Valid2FA = false and JWT set to nil. This should trigger the client to execute
// a subsequent two-factor authentication step. If the two-factor authentication
// step succeeds, *Twofactor.Valid = true and JWT is populated with the user credentials.
type Auth struct {
	Twofactor *Twofactor `json:"twofactor"`
	JWT       *JWT       `json:"jwt"`
}

// Twofactor encapsulates the state of a two-factor authentication process.
// If the user enabled two-factor authentication a Twofactor response is returned
// immediately from a successful user/password login with Count = 0.
// It is expected that the client will follow with a two-factor authentication
// request. If that request succeeds a JWT response (see below) is returned.
// If the request fails the Twofactor response is returned again with Valid = false.
// - Count is the number of attempts to complete the two-factor authentication
// - TenantID is the unique ID of the tenant of which the user is a member
// - UserID is the unique of the user account carrying out the authentication.
type Twofactor struct {
	Count    int    `json:"count"`
	Valid    bool   `json:"valid"`
	TenantID string `json:"tid"`
	UserID   string `json:"uid"`
}

// JWT encapsulates the user claims returned from a successful login
// workflow. If the user has not enabled two-factor authentication the
// response is returned immediately from a successful user/password login.
// If the user has enabled two-factor authentication, the JWT is returned
// at the completion of a subsequent successful two-factor authentication.
type JWT struct {
	JWTToken     string `json:"jwtToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"`
}

func (j *JWT) JSON() string {
	b, err := json.Marshal(j)
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

// Claims type
type Claims struct {
	Identity *Identity `json:"identity"`
	jwt.RegisteredClaims
	AuthClaims
}

// AuthClaims type
type AuthClaims struct {
	IDP      string   `json:"idp,omitempty"`
	ClientID string   `json:"client_id,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"`
	SID      string   `json:"sid,omitempty"`
	Scope    []string `json:"scope,omitempty"`
	AMR      []string `json:"amr,omitempty"`
}

// // RefreshClaims type
type RefreshClaims struct {
	TID string `json:"tid"`
	UID string `json:"uid"`
	jwt.RegisteredClaims
}

// ResetClaims type
type ResetClaims struct {
	TID string `json:"tid"`
	UID string `json:"uid"`
	jwt.RegisteredClaims
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
