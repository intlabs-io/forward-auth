package acc

import (
	authn "bitbucket.org/_metalogic_/authenticate"
	"github.com/golang-jwt/jwt/v4"
)

type LoginRequest struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

// RSA key creation expects lifetime expressed in seconds for the JWT and refresh tokens
type KeyRequest struct {
	KeyLife     int `json:"keyLife"`
	RefreshLife int `json:"refreshLife"`
}

// ClaimsResponse type
type ClaimsResponse struct {
	Identity *authn.Identity `json:"identity"`
	jwt.RegisteredClaims
	authn.AuthClaims
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
