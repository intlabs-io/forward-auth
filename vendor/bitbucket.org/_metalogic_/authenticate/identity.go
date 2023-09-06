package authn

import (
	"fmt"
	"log/slog"
)

// Identity encapsulates attributes used in user authorization
//   - ID - the ID of this user (unique within tenant)
//   - TID - the tenant ID of which this user is a member
//   - Name - a human readable name for user
//   - Email - the main email address of the user (unique within tenant);
//   - Superuser - whether the user is a superuser within tenant
//   - Classification - seecurity classification of user
//   - Permissions - permissions granted to user within tenant
//
// A user is granted one or more roles in a tenant. Roles
// define categories to which action permissions are assigned. Identity permissions
// represent the union of all permissions assigned by the user's roles and
// are computed at the time the user is authenitcated. Changes to role permissions
// will not take effect for the user until the next time the user authenticates.
type Identity struct {
	TenantID       string          `json:"tenantID"`
	UserID         string          `json:"userID"`
	Name           string          `json:"name"`
	Email          string          `json:"email"`
	Superuser      bool            `json:"superuser"`
	Classification *Classification `json:"classification"`
	Permissions    []*Permission   `json:"permissions"`
}

func (user *Identity) Username() (username string) {
	if user.UserID != "" {
		username = user.UserID
	}
	if user.Name != "" {
		if username == "" {
			username = user.Name
		} else {
			username = username + "," + user.Name
		}
	}
	return username
}

// CheckPermission returns true if user has action permission on category in the tenant
func (user *Identity) CheckPermission(tenantID, context, action, category string) (allow bool) {

	// if user is a superuser in the tenant then user has permission
	if user.Superuser && user.TenantID == tenantID {
		return true
	}

	slog.Debug(fmt.Sprintf("evaluating user permissions: %+v", user.Permissions))

	// example user permissions list:
	// [
	//	 {
	//     "context": "1b7c3bed-8472-4a54-9058-4154d345abf8",
	//     "actions": {
	//         "CONTENT": ["READ"],
	//         "MEDIA": ["ANNOTATE", "READ"]
	//      }
	//   },
	//   {
	//      "context": "5273d8a1-6bbd-4ccd-9bda-8340acb8cfe9",
	//      "actions": {
	//          "CONTENT": ["ALL"],
	//          "MEDIA": ["ALL"]
	//      }
	//   },
	//   {
	//      "context: "ccd660fc-5680-44b2-a570-17cf8229f694",
	//      "actions": {
	//          "ANY": ["ALL"]
	//      }
	//    }
	// ]
	for _, perm := range user.Permissions {
		slog.Debug(fmt.Sprintf("evaluating permission context %s against %s", perm.Context, context))
		if context == ContextsAll || context == perm.Context {
			actions := append(perm.CategoryActions[CategoryAny], perm.CategoryActions[category]...)
			slog.Debug(fmt.Sprintf("evaluating action %s against permitted actions %+v for category %s",
				action, actions, category))
			for _, a := range actions {
				if a == ActionAll || a == action {
					return true
				}
			}
			return false
		}
	}
	return false
}

func (user *Identity) Contexts() []string {
	contexts := make([]string, 0)
	for _, perm := range user.Permissions {
		if perm.Context == ContextsAll {
			contexts = []string{ContextsAll}
			break
		}
		contexts = append(contexts, perm.Context)
	}
	return contexts
}

// Role represents a named set of permissions for a tenant.
// Roles are assigned to credentials (eg a user, token etc).
// Example ADMIN role for a tenant ACME:
//
//		{
//		   "uid": "5273d8a1-6bbd-4ccd-9bda-8340acb8cfe9",
//	       "name": "ADMIN",
//	       "tenant": "ACME",
//         "description": "administrator has all actions on any category in all contexts",
//	       "permissions": [
//		      {
//		         "context": "ALL",
//		         "actions": {
//		            "ANY": ["ALL"],
//		         }
//		      }
//	       ]
//		 }
//
// Example REVIEW role for a tenant ACME:
//		{
//		   "uid": "5273d8a1-6bbd-4ccd-9bda-8340acb8cfe9",
//	       "name": "REVIEW",
//	       "tenant": "ACME",
//         "description": "a state reviewer has READE action on ANY category, and APPEND action on the JOURNAL in each state",
//	       "permissions": [
//		      {
//		         "context": "Alabama",
//		         "actions": {
//		            "ANY": ["READ"],
//                  "JOURNAL": ["APPEND"]
//		         }
//		      },
//		      {
//		         "context": "Alaska",
//		         "actions": {
//		            "ANY": ["READ"],
//                  "JOURNAL": ["APPEND"]
//		         }
//		      }
//            ...
//	       ]
//		 }
//

type Role struct {
	UID         string       `json:"id"`
	TenantID    string       `json:"tid"`
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
}

// Permission defines a collection of permitted actions on categories; for example
//
//		{
//		   "context": "5273d8a1-6bbd-4ccd-9bda-8340acb8cfe9",
//		   "actions": {
//	           "ANY": ["READ"],
//		       "CONTENT": ["ALL"],
//		       "MEDIA": ["READ", "UPDATE", "DELETE"]
//		    }
//		 }
//
// In this example both category ANY and category MEDIA permit READ action.
type Permission struct {
	Context         string              `json:"context"`
	CategoryActions map[string][]string `json:"actions"`
}

// CategoryActions encapsulates allowed actions on a category
// type CategoryActions struct {
// 	Category string   `json:"categoryCode"`
// 	Actions  []string `json:"actions"`
// }

type Action string

type Category string
type CategoryActions map[Category][]Action
