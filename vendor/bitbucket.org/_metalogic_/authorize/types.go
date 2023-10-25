package authz

type EmailRequest struct {
	Email string `json:"email"`
}

// UserRequest  type
type UserRequest struct {
	UID     string `json:"uid"`
	Email   string `json:"email"`
	Status  string `json:"status"`
	Comment string `json:"comment,omitempty"`
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

func (i *Identity) UserID() string {
	if i.UID == nil {
		return ""
	}
	return *i.UID
}

func (i *Identity) TenantID() string {
	if i.TID == nil {
		return ""
	}
	return *i.TID
}

func (i *Identity) Contexts() []string {
	contexts := make([]string, 1)
	for _, perm := range i.UserPermissions {
		if perm.Context == "ALL" {
			contexts = []string{"ALL"}
			break
		}
		contexts = append(contexts, perm.Context)
	}
	return contexts
}

type Classification struct {
	Authority string `json:"authority"`
	Level     string `json:"level"`
}

// UserPermission defines the permissions of a tenant user
type UserPermission struct {
	Context     string       `json:"context"`
	Permissions []Permission `json:"permissions"`
}

//	[{
//		"permissions": {
//			"context": "5273d8a1-6bbd-4ccd-9bda-8340acb8cfe9",
//			"permissions": [{
//				"actions": ["ALL"],
//				"categoryCode": "CONTENT"
//			}, {
//				"actions": ["ALL"],
//				"categoryCode": "MEDIA"
//			}]
//		}
//	}]
//
// Permission type
type Permission struct {
	Category string   `json:"categoryCode"`
	Actions  []string `json:"actions"`
}
