package acc

import (
	"encoding/json"
	"fmt"

	authn "bitbucket.org/_metalogic_/authenticate"
	"github.com/golang-jwt/jwt/v4"
)

// Credentials type
type Credentials struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type LoginRequest struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

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

// RSA key creation expects lifetime expressed in seconds for the JWT and refresh tokens
type KeyRequest struct {
	KeyLife     int `json:"keyLife"`
	RefreshLife int `json:"refreshLife"`
}

// RefreshToken type
type RefreshToken struct {
	JWTRefresh string `json:"jwtRefresh"`
}

/***************
 * Claims Types
 ***************/

// Claims type
type Claims struct {
	Identity *authn.Identity `json:"identity"`
	jwt.RegisteredClaims
	AuthClaims
}

// RefreshClaims type
type RefreshClaims struct {
	TID string `json:"tid"`
	UID string `json:"uid"`
	jwt.RegisteredClaims
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

// ClaimsResponse type
type ClaimsResponse struct {
	Identity *authn.Identity `json:"identity"`
	jwt.RegisteredClaims
	AuthClaims
}

// ResetClaims type
type ResetClaims struct {
	TID string `json:"tid"`
	UID string `json:"uid"`
	jwt.RegisteredClaims
}

// initiates user account recovery
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// executed by authenticated user as normal change password
type ChangePasswordRequest struct {
	Email           string `json:"email"`
	CurrentPassword string `json:"currentPassword"`
	Password        string `json:"password"`
}

// executed by a user at completion of user account recovery
type SetPasswordRequest struct {
	Password string `json:"password"`
}

type RoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
