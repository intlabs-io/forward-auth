package acc

import (
	"encoding/json"
	"fmt"
	"time"

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
	Identity   *authn.Identity `json:"identity"`
	JWT        string          `json:"jwt"`
	JwtRefresh string          `json:"jwtRefresh"`
	ExpiresAt  int64           `json:"expiresAt"`
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
	JwtRefresh string `json:"jwtRefresh"`
}

// Identity type
// TODO replace with authn.Identity
// type Identity struct {
// 	TID             *string          `json:"tid"`
// 	UID             *string          `json:"uid"`
// 	Name            *string          `json:"name"`
// 	Email           *string          `json:"email"`
// 	Superuser       bool             `json:"superuser"`
// 	Classification  *Classification  `json:"classification"`
// 	UserPermissions []UserPermission `json:"userPerms"`
// }

// TODO replace with authn.Classification
// type Classification struct {
// 	Authority string `json:"authority"`
// 	Level     string `json:"level"`
// }

/******************************
 * User registrations
 ******************************/

type CreateUserRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	Superuser bool   `json:"superuser"`
	Token     string `json:"token"`
	Status    string `json:"status"`
	Comment   string `json:"comment"`
	Profile   struct {
		Firstname     string `json:"firstName"`
		Lastname      string `json:"lastName"`
		PreferredName string `json:"preferredName"`
		Birthdate     string `json:"birthdate"`
		Gender        string `json:"gender"`
	}
	Contacts []Contact `json:"contacts"`
	Role     struct {
		Name    string `json:"name"`
		Context string `json:"context"`
	} `json:"role"`
}

type UpdateUserRequest struct {
	Password  string `json:"password"`
	Superuser *bool  `json:"superuser"`
	Status    string `json:"status"`
	Comment   string `json:"comment"`
	Profile   struct {
		Firstname string `json:"firstName"`
		Lastname  string `json:"lastName"`
		Tel       string `json:"tel"`
	}
	Role struct {
		Name    string `json:"name"`
		Context string `json:"context"`
	} `json:"role"`
}

/******************************
 * User account and profile
 ******************************/

type User struct {
	TID          string    `json:"tid"`
	UID          string    `json:"uid"`
	Email        string    `json:"email"`
	Password     string    `json:"password"`
	Superuser    bool      `json:"superuser"`
	Token        string    `json:"token"`
	Status       string    `json:"status"`
	Comment      string    `json:"comment,omitempty"`
	Profile      Profile   `json:"profile"`
	Contacts     []Contact `json:"contacts"`
	Declarations []string  `json:"declarations,omitempty"`
}

type Profile struct {
	FirstName     string    `json:"firstName"`
	LastName      string    `json:"lastName"`
	PreferredName string    `json:"preferredName"`
	Gender        string    `json:"gender"`
	Birthdate     time.Time `json:"birthdate"`
}

type Contact struct {
	Type        string          `json:"contactType"`
	Channel     string          `json:"channelType"`
	Description string          `json:"description"`
	Reference   json.RawMessage `json:"reference"`
}

// type Role struct {
// 	Name        string `json:"name"`
// 	Description string `json:"description"`
// }

// type UserRole struct {
// 	Name    string `json:"name"`
// 	Context string `json:"context"`
// }

// UserPermission defines the permissions of a tenant user
// TODO replace with authn.UserPermission
// type UserPermission struct {
// 	Context     string       `json:"context"`
// 	Permissions []Permission `json:"permissions"`
// }

// [{"permissions":{"context": "5273d8a1-6bbd-4ccd-9bda-8340acb8cfe9", "permissions": [{"actions": ["ALL"], "categoryCode": "CONTENT"}, {"actions": ["ALL"], "categoryCode": "MEDIA"}]}}]

// Permission type
// TODO replace with authn.Permission
// type Permission struct {
// 	Category string   `json:"categoryCode"`
// 	Actions  []string `json:"actions"`
// }

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
