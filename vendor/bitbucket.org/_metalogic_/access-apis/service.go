package acc

import "time"

// Common defines the common service interface
type Common interface {
	Health() error
	Info() map[string]string
}

// Service defines the Auth service interface
type Service interface {
	Common
	ID() string
	Close() error
	Driver() string
	DSN() string

	// base methods
	TenantStatusTypes() (statusesJSON string, err error)
	UserStatusTypes() (statusesJSON string, err error)

	// tenant methods
	Actions(tid string) (actionsJSON string, err error)
	AcceptAndActivate(sessionID, tid, token, email, passwordHash, firstName, lastName string, declarationGUIDs []string) (acceptJSON string, err error)
	AddTenantUserRole(sessionID, tid, uid, rid string) (institutionUserRoleJSON string, err error)
	AddPermissionToRole(sessionID, tid, rid, context, categoryCode, actionCode string) (permissionJSON string, err error)
	AssignUserRole(sessionID, tid, uid, rid string) (roleJSON string, err error)
	Categories(tid string) (categoriesJSON string, err error)
	Category(tid, code string) (categoryJSON string, err error)
	CategoryContexts(tid, code string) (categoryContextJSON string, err error)
	ChangeAccountEmail(sessionID, tid, uid, emailGUID string) (userJSON string, err error)
	CreateCategoryContext(sessionID, tid, code, categoryCode, description string, active bool) (categoryContextJSON string, err error)
	CreateRoleForTenant(sessionID, tid, name, description string) (roleJSON string, err error)

	// Tenant User Accounts
	CreateUser(sessionID, tid, email, password string, superuser bool, status, comment, firstname, lastname, tel, role, context string) (userJSON string, err error)

	// Tenant Context Requests
	Contexts(tid string) (contextsJSON string, err error)
	Context(tid, cid string) (contextJSON string, err error)
	EnsureContext(sessionID, tid string, ensureRequest *EnsureContextRequest) (contextJSON string, err error)
	UpdateContext(sessionID, tid, cid string, updateRequest *UpdateContextRequest) (contextJSON string, err error)
	DeleteContext(tid, cid string) (deleteJSON string, err error)

	// Tenant User Registration Requests
	RegistrationRequests(tid string) (requestsJSON string, err error)
	RegistrationRequest(tid, rid string) (requestJSON string, err error)
	DeleteRegistrationRequest(tid, rid string) (deleteJSON string, err error)
	RequestRegistration(sessionID, tid, email, name, tel, note string) (requestJSON string, err error)
	UpdateRegistrationRequest(sessionID, tid, ridd, action string) (requestJSON string, err error)

	// API Keys
	APIKey(tid, name string) (keyJSON string, err error)
	CreateAPIKey(sessionID, tid, name, apiKey string) (keyJSON string, err error)
	DisableAPIKey(sessionID, tid, name string) (err error)

	// RSA Keys
	RSA(tid string) (key []byte, keyLife, refreshLife time.Duration, err error)
	PublicKey(tid string) (pubPEM []byte, err error)
	CreateRSAKey(sessionID, tid string, keyLife, refreshLife int) (keyJSON string, err error)
	DisableRSAKey(sessionID, tid string) (err error)

	// User Roles
	DeleteTenantUserRole(tid, uid, rid string) (rolesJSON string, err error)
	DeleteRole(sessionID, tid, rid string) (err error)
	DeleteUser(sessionID, tid, uid string) (deleteJSON string, err error)
	Invitation(tid, email, token string) (userJSON string, err error)
	Invitations(tid, email, status string) (invitationsJSON string, err error)
	InviteUser(sessionID, tid, app, email string, rids []string) (invitationJSON string, err error)
	Login(tid, email, password string) (identityJSON string, err error)
	Refresh(tid, uid string) (identityJSON string, err error)
	PasswordHash(tid, uid string) (hash string, err error)

	ReinviteUser(sessionID, tid, app, email string) (invitationJSON string, err error)
	RemovePermissionFromRole(sessionID, tid, rid, context, categoryCode, actionCode string) (permissionJSON string, err error)
	RemoveUserRole(tid, uid, rid string) (roleJSON string, err error)
	Role(tid string, rid string) (roleJSON string, err error)
	Roles(tid string) (rolesJSON string, err error)
	RoleUsers(tid, rid string) (institutionUserRolesJSON string, err error)
	SetPassword(sessionID, tid, uid, hash string) (err error)

	UpdateCategoryContext(sessionID, tid, code, updateCode, categoryCode, description string, active *bool) (categoryContextJSON string, err error)
	UpdateInvitation(sessionID, tid, token, email, status string) (updateInvitationJSON string, err error)
	UpdateRole(sessionID, tid, rid, name, description string) (roleJSON string, err error)
	UpdateUser(sessionID, tid, uid, password string, superuser *bool, status, comment, roleName, context string) (userJSON string, err error)
	User(tid, uid string) (userJSON string, err error)
	UserUID(tid, email string) (uid string, err error)
	Users(tid, email, name, status string, offset, limit int) (usersJSON string, err error)
	UserRoles(tid, uid string) (institutionUserRolesJSON string, err error)
	UsersWithRoles(tid string) (rolesJSON string, err error)

	ValidateResetToken(tid, token string) (err error)
	ValidateInvitation(sessionID, tid, email, token string) (validateInvitationJSON string, err error)
}
