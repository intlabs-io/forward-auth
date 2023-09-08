package acc

import (
	"encoding/json"
	"time"
)

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
