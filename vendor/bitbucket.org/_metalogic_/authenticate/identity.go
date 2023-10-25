package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const issuedAtLeeway = 1

// CustomClaims type
type CustomClaims struct {
	Identity *Identity `json:"identity"`
	jwt.RegisteredClaims
}

// override default Valid() method to allow clock drift of up to issuedAtLeewaySecs seconds
func (c *CustomClaims) Valid() (err error) {
	c.RegisteredClaims.IssuedAt.Add(-issuedAtLeeway * time.Second)
	err = c.RegisteredClaims.Valid()
	c.RegisteredClaims.IssuedAt.Add(issuedAtLeeway * time.Second)
	return err
}

// Identity encapsulates attributes used in user authorization.
//   - TenantID - the tenant ID of which this user is a member
//   - UserID - the ID of this user (unique in tenant)
//   - Name - a human readable name for user
//   - Email - the main email address of the user (unique in tenant);
//   - Superuser - whether the user is a superuser in tenant
//   - Classification - seecurity classification of user in tenant
//   - Permissions - permissions granted to user in tenant
//
// A user is granted one or more roles in a tenant. Roles
// define actions permission on categories. For example, an EDITOR
// role might define the following actions on categories CONTENT and MEDIA
//
//	CONTENT: ["CREATE", "READ", "UPDATE", "DELETE"]
//	MEDIA: ["READ"]
//	etc
//
// Roles are assigned to a user in one ore more contexts (or domains).
// User permissions are the union of all permissions assigned by the user's roles
// and are computed at the time the user is authenticated. Changes to role permissions
// will not take effect for the user until the next time the user authenticates.
type Identity struct {
	TenantID       string          `json:"tid"`
	UserID         string          `json:"uid"`
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

func FromJWT(tknStr string, keyFunc jwt.Keyfunc) (identity *Identity, err error) {

	// Claims type
	type Claims struct {
		Identity *Identity `json:"identity"`
		jwt.RegisteredClaims
	}

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT token and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (that is expired according to the expiry time set at sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims, keyFunc)

	if err != nil {
		slog.Error(err.Error())
		return identity, err
	}

	if !tkn.Valid {
		return identity, fmt.Errorf("JWT token in request is expired")
	}

	if slog.Default().Enabled(context.TODO(), slog.LevelDebug) {
		m, err := json.Marshal(claims)
		if err != nil {
			slog.Error(fmt.Sprintf("failed to marshal claims: %+v", claims))
		} else {
			slog.Debug("marshaled JWT", "claims", m)
		}
	}

	return claims.Identity, nil
}

// HasPermission returns true if user has action permission on category in tenant and context
func (user *Identity) HasPermission(tenantID, context, action, category string) (allow bool) {

	// if user is a superuser in the tenant then user has permission
	if user.Superuser && user.TenantID == tenantID {
		return true
	}

	slog.Debug(fmt.Sprintf("evaluating user permissions: %+v", user.Permissions))

	actions := []string{}
	for _, perm := range user.Permissions {
		slog.Debug(fmt.Sprintf("evaluating permission context %s against %s", perm.Context, context))
		if perm.Context == ContextsAll || perm.Context == context {
			actions = append(actions, perm.CategoryActions[CategoryAny]...)
			actions = append(actions, perm.CategoryActions[category]...)
		}
	}

	if len(actions) == 0 {
		return false
	}

	slog.Debug(fmt.Sprintf("testing against allowed actions %+v", actions))

	for _, a := range actions {
		if a == ActionAll || a == action {
			return true
		}
	}
	return false
}

func (user *Identity) Contexts() []string {
	contexts := make([]string, 0)
	for _, perm := range user.Permissions {
		// if perm.Context == ContextsAll {
		// 	contexts = []string{ContextsAll}
		// 	break
		// }
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
//         "description": "a province reviewer has READ action on ANY category, and APPEND action on the JOURNAL in each province",
//	       "permissions": [
//		      {
//		         "context": "Alberta",
//		         "actions": {
//		            "ANY": ["READ"],
//                  "JOURNAL": ["APPEND"]
//		         }
//		      },
//		      {
//		         "context": "British Columbia",
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
