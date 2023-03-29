package acc

import (
	"github.com/golang-jwt/jwt/v4"
)

type Credentials struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

// Credentials type
type LoginRequest struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

// Auth type returned by a successful authentication
type Auth struct {
	Identity   *Identity `json:"identity"`
	JWT        string    `json:"jwt"`
	JwtRefresh string    `json:"jwtRefresh"`
	ExpiresAt  int64     `json:"expiresAt"`
}

// RSA key creation expects lifetime expressed in seconds for the JWT and refresh tokens
type KeyRequest struct {
	KeyLife     int `json:"keyLife"`
	RefreshLife int `json:"refreshLife"`
}

// RefreshToken type
type RefreshToken struct {
	JwtRefresh string `json:"jwtRefresh"`
}

// Identity type
type Identity struct {
	TID             *string          `json:"tid"`
	UID             *string          `json:"uid"`
	Name            *string          `json:"name"`
	Email           *string          `json:"email"`
	Superuser       bool             `json:"superuser"`
	Classification  *Classification  `json:"classification"`
	UserPermissions []UserPermission `json:"userPerms"`
}

type Classification struct {
	Authority string `json:"authority"`
	Level     string `json:"level"`
}

// User type
type UserRequest struct {
	UID     string `json:"uid"`
	Email   string `json:"email"`
	Status  string `json:"status"`
	Comment string `json:"comment,omitempty"`
}

// UserPermission defines the permissions of a tenant user
type UserPermission struct {
	Context     string       `json:"context"`
	Permissions []Permission `json:"permissions"`
}

// [{"permissions":{"context": "5273d8a1-6bbd-4ccd-9bda-8340acb8cfe9", "permissions": [{"actions": ["ALL"], "categoryCode": "CONTENT"}, {"actions": ["ALL"], "categoryCode": "MEDIA"}]}}]

// Permission type
type Permission struct {
	Category string   `json:"categoryCode"`
	Actions  []string `json:"actions"`
}

// User info to invite
type InviteUserRequest struct {
	App   string   `json:"app"`
	Email string   `json:"email"`
	Roles []string `json:"rids,omitempty"`
}

type InvitationRequest struct {
	Email        string   `json:"email"`
	Status       string   `json:"status"`
	FirstName    string   `json:"firstName"`
	LastName     string   `json:"lastName"`
	Password     string   `json:"password"`
	Declarations []string `json:"declarations"`
}

/***************
 * Claims Types
 ***************/

// Claims type
type Claims struct {
	Identity *Identity `json:"identity"`
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
	Identity *Identity `json:"identity"`
	jwt.RegisteredClaims
	AuthClaims
}

// ResetClaims type
type ResetClaims struct {
	UID string `json:"uid"`
	jwt.RegisteredClaims
}

type ResetPasswordRequest struct {
	Email     string `json:"email"`
	ReturnUrl string `json:"returnUrl"`
}

type ChangePasswordRequest struct {
	Token           string `json:"token,omitempty"`
	CurrentPassword string `json:"currentPassword,omitempty"`
	Password        string `json:"password"`
}

type RoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
