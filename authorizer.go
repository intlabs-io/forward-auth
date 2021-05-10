package fauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"bitbucket.org/_metalogic_/eval"
	"bitbucket.org/_metalogic_/ident"
	"bitbucket.org/_metalogic_/log"
	"bitbucket.org/_metalogic_/pat"
	jwt "github.com/dgrijalva/jwt-go"
)

const (
	// ANY wildcard category matches any individual category (eg ADM, FEE, INST, etc)
	ANY = "ANY"
	// ALL wildcard action matches any of GET, PUT, POST, DELETE
	ALL = "ALL"
)

// Action constants as defined in database table [auth].[ACTIONS]
// HTTP methods are mapped to an action
const (
	CREATE = "CREATE"
	READ   = "READ"
	UPDATE = "UPDATE"
	DELETE = "DELETE"
)

// Auth type holds data for authorization
// - jwtHeader is the name of the header containing the user's JWT
// - idType is a string with value either "string" or "struct":
//   if "string" then the value of Claim.Identity is a string;
//   if "struct" then the value of Claim.Identity is the Identity struct defined in this package
// - keyFunc is a function passed to JWT parse function to return the key for decrypting the JWT token
// - tokens maps token values passed in a request to token names referenced in
//   access control functions; eg: bearer(ROOT_TOKEN) returns true if the bearer
//   auth token in the request maps to the name ROOT_TOKEN
// - blocks is a map of subjects (usernames, hostnames, IP addresses) to be denied
//   access; subject names must be unique for all subjects
// an instance of Auth is passed to handlers to drive authorization calculations
type Auth struct {
	jwtHeader string
	keyFunc   func(token *jwt.Token) (interface{}, error)
	tokens    map[string]string
	blocks    map[string]bool
}

// NewAuth returns a new RSA Auth
func NewAuth(jwtHeader string, publicKey, secret []byte, tokens map[string]string, blocks map[string]bool) (auth *Auth, err error) {
	auth = &Auth{
		jwtHeader: jwtHeader,
		tokens:    tokens,
		blocks:    blocks,
	}
	rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return auth, err
	}
	auth.keyFunc = func(token *jwt.Token) (key interface{}, err error) {
		switch token.Method.Alg() {
		case "HS256":
			return secret, nil
		case "RS256":
			return rsaKey, nil
		}
		return key, fmt.Errorf("invalid JWT alg: %s", token.Method.Alg())
	}
	return auth, nil
}

// CheckBearerAuth checks for token in list of tokens returning true if found
func (auth *Auth) CheckBearerAuth(token string, tokens ...string) bool {
	for _, t := range tokens {
		if t == auth.tokens[token] {
			log.Debugf("allowing by bearer token '%s'", redact(token))
			return true
		}
	}
	log.Debugf("rejecting by bearer auth for accepted tokens: %v", tokens)
	return false
}

// CheckJWT returns true if jwt has action permission on category in the tenantID
func (auth *Auth) CheckJWT(jwt, tenantID, category, action string) bool {
	if jwt == "" {
		return false
	}

	var err error
	var identity *Identity
	if identity, err = jwtIdentity(jwt, auth); err != nil {
		log.Errorf("JWT found in request is invalid: %s", err)
		return false
	}

	log.Debugf("identity found in JWT: %s", identity)

	if identity.Root {
		return true
	}
	log.Debugf("evaluating user permissions: %v+", identity.UserPermissions)
	for _, role := range identity.UserPermissions {
		if role.TenantID == tenantID {
			for _, perm := range role.Permissions {
				if perm.Category == ANY || perm.Category == category {
					for _, a := range perm.Action {
						if a == ALL || a == action {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func (auth *Auth) JWTIdentity(tknStr string) (identity *Identity, err error) {
	return jwtIdentity(tknStr, auth)
}

// Root returns true if jwt has root privilege
func (auth *Auth) Root(jwt string) bool {
	if jwt == "" {
		return false
	}

	var err error
	var identity *Identity
	if identity, err = jwtIdentity(jwt, auth); err != nil {
		log.Errorf("JWT found in request is invalid: %s", err)
		return false
	}

	log.Debugf("identity found in JWT: %s", identity)

	return identity.Root
}

// User returns the user GUID in jwt
func (auth *Auth) User(jwt string) (guid string) {
	if jwt == "" {
		return guid
	}

	var err error
	var identity *Identity
	if identity, err = jwtIdentity(jwt, auth); err != nil {
		log.Errorf("JWT found in request is invalid: %s", err)
		return guid
	}

	log.Debugf("identity found in JWT: %s", identity)

	return identity.User
}

// Identity type
type Identity struct {
	User            string           `json:"userGUID"`
	Username        string           `json:"username"`
	Root            bool             `json:"root"`
	UserPermissions []UserPermission `json:"userPerms"`
}

func (ident *Identity) String() string {
	return ident.Username
}

// UserPermission defines the permissions of a user for a tenant
type UserPermission struct {
	TenantID    string                `json:"tenantID"`
	Permissions []CategoryPermissions `json:"perms"`
}

// CategoryPermissions type
type CategoryPermissions struct {
	Category string   `json:"category"`
	Action   []string `json:"actions"`
}

func jwtIdentity(tknStr string, auth *Auth) (identity *Identity, err error) {

	// ClaimsOld type
	type ClaimsOld struct {
		Identity string `json:"identity"`
		jwt.StandardClaims
	}
	// Initialize a new instance of `Claims`
	old := &ClaimsOld{}

	// Parse the JWT token and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (that is expired according to the expiry time set at sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, old, auth.keyFunc)

	if err == nil {
		if !tkn.Valid {
			return identity, fmt.Errorf("JWT token in request is expired")
		}
		log.Debugf("JWT Claims: %+v", old)
		identity = &Identity{}
		err = json.Unmarshal([]byte(old.Identity), identity)
		if err == nil {
			return identity, nil
		}
	}

	log.Debug("failed to parse Claim as old - continuing")

	// Claims type
	type Claims struct {
		Identity *Identity `json:"identity"`
		jwt.StandardClaims
	}
	// Initialize a new instance of `Claims`
	new := &Claims{}

	// Parse the JWT token and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (that is expired according to the expiry time set at sign in),
	// or if the signature does not match
	tkn, err = jwt.ParseWithClaims(tknStr, new, auth.keyFunc)

	if err != nil {
		log.Error(err)
		return identity, err
	}

	if !tkn.Valid {
		return identity, fmt.Errorf("JWT token in request is expired")
	}

	log.Debugf("JWT Claims: %+v", new)

	identity = new.Identity

	return identity, err
}

// Action returns an action from an HTTP method
func Action(method string) string {
	switch method {
	case "GET":
		return READ
	case "POST":
		return CREATE
	case "PUT":
		return UPDATE
	case "DELETE":
		return DELETE
	default:
		return "UNDEFINED"
	}
}

// Handler returns a handler implementing rule evaluation for an auth environment and authorizer
func Handler(rule Rule, auth *Auth) func(method, path string, params map[string][]string, header http.Header) (status int, message, username string) {
	if rule.Expression == "true" {
		return pat.AllowHandler
	}
	if rule.Expression == "false" {
		return pat.DenyHandler
	}
	return func(method, path string, params map[string][]string, header http.Header) (status int, message, username string) {

		// Request Headers
		authHeader := header.Get("Authorization")

		var token string
		if authHeader != "" {
			// Get the Bearer auth token
			splitToken := strings.Split(authHeader, "Bearer ")
			if len(splitToken) == 2 {
				token = splitToken[1]
			}
		}

		jwt := header.Get(auth.jwtHeader)

		credentials := &ident.Credentials{
			Token: token,
			JWT:   jwt,
		}

		if jwt != "" {
			username = auth.User(jwt)
		}

		if t, err := evaluate(rule.Expression, params, auth, credentials); err != nil {
			message := fmt.Sprintf("%s %s failed evaluation for rule %s: %s", method, path, rule.Expression, err)
			log.Error(message)
			return http.StatusForbidden, message, username
		} else if t {
			message := fmt.Sprintf("%s %s allowed by rule %s", method, path, rule.Expression)
			log.Debug(message)
			return http.StatusOK, message, username
		} else {
			message := fmt.Sprintf("%s %s denied by rule %s", method, path, rule.Expression)
			log.Debug(message)
			return http.StatusForbidden, message, username
		}
	}
}

func evaluate(expr string, paramMap map[string][]string, auth *Auth, credentials *ident.Credentials) (result bool, err error) {
	log.Debugf("evaluating expr '%s' with params %v, auth %v, credentials %v", expr, paramMap, auth, credentials)
	// define builtins
	functions := map[string]eval.ExpressionFunction{
		// return true if the value of one of the bearer tokens is valid in the environment
		// eg: bearer('ROOT_TOKEN', ...)
		"bearer": func(args ...interface{}) (interface{}, error) {
			if credentials.Token == "" {
				return false, nil
			}
			var tokens []string
			for _, arg := range args {
				tokens = append(tokens, arg.(string))
			}
			log.Debugf("calling bearer(%v)", tokens)
			return auth.CheckBearerAuth(credentials.Token, tokens...), nil
		},
		// return the binding of a path or query parameter
		// eg: param(':tenantID')
		"param": func(args ...interface{}) (interface{}, error) {
			param := args[0].(string)
			log.Debugf("calling param(%s)", param)
			if v, ok := paramMap[param]; ok {
				return v[0], nil
			}
			return "", nil
		},
		// return true if identity has role permission in tenant
		// eg: role(tenantID('KPU'),'ADM','READ')
		"role": func(args ...interface{}) (interface{}, error) {
			tenantID, _ := args[0].(string)
			category := args[1].(string)
			action := args[2].(string)
			log.Debugf("calling role(%s,%s,%s)", tenantID, category, action)
			return auth.CheckJWT(credentials.JWT, tenantID, category, action), nil
		},
		// return true if identity has role permission in tenant
		// eg: role(epbcid(KPU),ADM,READ)
		"root": func(args ...interface{}) (interface{}, error) {
			log.Debug("calling root()")
			return auth.Root(credentials.JWT), nil
		},
	}

	expression, err := eval.NewEvaluableExpressionWithFunctions(expr, functions)
	if err != nil {
		log.Error(err)
		return result, err
	}

	parameters := make(map[string]interface{}, 8)
	for k, v := range paramMap {
		parameters[k] = v
	}

	parameters["EPBC_API_TOKEN"] = "733acb21-3ca3-4f54-a9b0-1d219c659d1c"

	log.Debugf("evaluating expression %s", expr)
	val, err := expression.Evaluate(parameters)
	if err != nil {
		log.Error(err)
		return result, err
	}

	return val.(bool), nil
}

func redact(secret string) string {
	l := len(secret)
	if l <= 10 {
		return "*REDACTED*"
	}
	return secret[:4] + " *REDACTED* " + secret[l-4:]
}
