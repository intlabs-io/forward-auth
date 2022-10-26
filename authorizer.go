package fauth

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"bitbucket.org/_metalogic_/config"
	"bitbucket.org/_metalogic_/eval"
	"bitbucket.org/_metalogic_/httpsig"
	"bitbucket.org/_metalogic_/ident"
	"bitbucket.org/_metalogic_/log"
	"bitbucket.org/_metalogic_/pat"
	"github.com/golang-jwt/jwt/v4"
)

const (
	// ANY wildcard category matches any individual category (eg ADM, FEE, INST, etc)
	ANY = "ANY"
	// ALL wildcard action matches any of GET, PUT, POST, DELETE, PATCH
	ALL = "ALL"
)

// Action constants as defined in database table [auth].[ACTIONS]
// HTTP methods are mapped to an action
const (
	CREATE = "CREATE"
	READ   = "READ"
	UPDATE = "UPDATE"
	DELETE = "DELETE"
	EXISTS = "EXISTS"
)

// Auth type holds data for authorization
//   - jwtHeader is the name of the header containing the user's JWT
//   - idType is a string with value either "string" or "struct":
//     if "string" then the value of Claim.Identity is a string;
//     if "struct" then the value of Claim.Identity is the Identity struct defined in this package
//   - keyFunc is a function passed to JWT parse function to return the key for decrypting the JWT token
//   - tokens maps token values passed in a request to token names referenced in
//     access control functions; eg: bearer(ROOT_TOKEN) returns true if the bearer
//     auth token in the request maps to the token name ROOT_TOKEN
//   - blocks is a map of subjects (usernames, hostnames, IP addresses) to be denied
//     access; subject names must be unique for all subjects
//
// an instance of Auth is passed to handlers to drive authorization calculations
type Auth struct {
	runMode    string
	jwtHeader  string
	keyFunc    func(token *jwt.Token) (interface{}, error)
	publicKeys map[string]*rsa.PublicKey
	tokens     map[string]string
	blocks     map[string]bool
	overrides  map[string]string
	mutex      sync.RWMutex
	hostMuxers map[string]*pat.HostMux
}

// NewAuth returns a new RSA Auth
func NewAuth(acs *AccessSystem, jwtHeader string, publicKey, secret []byte) (auth *Auth, err error) {
	auth = &Auth{
		jwtHeader:  jwtHeader,
		hostMuxers: make(map[string]*pat.HostMux),
		publicKeys: make(map[string]*rsa.PublicKey),
		tokens:     acs.Tokens,
		blocks:     acs.Blocks,
	}

	auth.setRSAPublicKeys(acs.PublicKeys)
	err = auth.setAccess(acs.Checks, false)
	if err != nil {
		return auth, err
	}

	rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return auth, err
	}
	// support JWT signing by either symmetric secret key or RSA public/private key
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
func (auth *Auth) CheckJWT(jwt, tenantID, context, category, action string) bool {
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
	log.Debugf("evaluating user permissions: %+v", identity.Permissions)
	for _, role := range identity.Permissions {
		if strings.EqualFold(role.TenantID, tenantID) {
			for _, perm := range role.Actions {
				if (perm.Context == ALL || perm.Context == context) && (perm.Category == ANY || perm.Category == category) {
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

	return *identity.UID
}

// Identity type
type Identity struct {
	UID            *string             `json:"uid"`
	Name           *string             `json:"name"`
	Root           bool                `json:"superuser"`
	Classification *string             `json:"classification"`
	Permissions    []TenantPermissions `json:"userPerms"`
}

func (ident *Identity) String() string {
	return *ident.Name
}

// TenantPermissions defines the permissions of a user for a tenant
type TenantPermissions struct {
	TenantID string            `json:"tenantID"`
	Actions  []CategoryActions `json:"perms"`
}

// CategoryActions type
type CategoryActions struct {
	Context  string   `json:"context"`
	Category string   `json:"category"`
	Action   []string `json:"actions"`
}

func jwtIdentity(tknStr string, auth *Auth) (identity *Identity, err error) {

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
	tkn, err := jwt.ParseWithClaims(tknStr, claims, auth.keyFunc)

	if err != nil {
		log.Error(err)
		return identity, err
	}

	if !tkn.Valid {
		return identity, fmt.Errorf("JWT token in request is expired")
	}
	log.Debugf("JWT Claims: %+v", claims)

	return claims.Identity, nil
}

// Action returns an action from an HTTP method
func Action(method string) string {
	switch method {
	case "GET", "OPTIONS":
		return READ
	case "POST":
		return CREATE
	case "PUT", "PATCH":
		return UPDATE
	case "DELETE":
		return DELETE
	case "HEAD":
		return EXISTS
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

		u, err := url.Parse(path)
		if err != nil { // shouldn't happen
			log.Error(err)
			return http.StatusForbidden, message, username
		}

		// get signature verifier
		var verifier httpsig.Verifier
		if header.Get(string(httpsig.Signature)) != "" {
			verifier, err = httpsig.NewForwardAuthVerifier(header, method, path, u.RawQuery)
			if err != nil {
				log.Warning(fmt.Sprintf("found signature header but failed to get verifier: %s", err))
			}
		}

		if t, err := evaluate(rule.Expression, params, auth, credentials, verifier); err != nil {
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

func (auth *Auth) setAccess(checks *HostChecks, refresh bool) error {
	auth.overrides = checks.Overrides

	// create Pat Host Muxers from Checks
	for _, group := range checks.HostGroups {
		// default to deny
		hostMux := pat.NewDenyMux()
		if group.Default == "allow" {
			hostMux = pat.NewAllowMux()
		}
		// each host in a group shares the hostMux
		for _, host := range group.Hosts {
			if v, ok := auth.overrides[host]; ok {
				log.Warningf("%s override on host %s disables defined host checks", v, host)
			}
			if _, ok := auth.getMux(host); !refresh && ok {
				log.Errorf("ignoring duplicate host checks for %s", host)
				continue
			}
			auth.setMux(host, hostMux)
		}
		// add path prefixes to hostMux
		for _, check := range group.Checks {
			// deny if method + path is not found
			pathPrefix := hostMux.AddPrefix(check.Base, pat.NotFoundHandler)
			for _, path := range check.Paths {
				if r, ok := path.Rules["GET"]; ok {
					pathPrefix.Get(path.Path, Handler(r, auth))
				}
				if r, ok := path.Rules["POST"]; ok {
					pathPrefix.Post(path.Path, Handler(r, auth))
				}
				if r, ok := path.Rules["PUT"]; ok {
					pathPrefix.Put(path.Path, Handler(r, auth))
				}
				if r, ok := path.Rules["PATCH"]; ok {
					pathPrefix.Patch(path.Path, Handler(r, auth))
				}
				if r, ok := path.Rules["DELETE"]; ok {
					pathPrefix.Del(path.Path, Handler(r, auth))
				}
				if r, ok := path.Rules["HEAD"]; ok {
					pathPrefix.Head(path.Path, Handler(r, auth))
				}
				if r, ok := path.Rules["OPTIONS"]; ok {
					pathPrefix.Options(path.Path, Handler(r, auth))
				}
			}
		}
	}
	return nil
}

func (auth *Auth) setRSAPublicKeys(publicKeys map[string]string) {
	auth.mutex.Lock()
	defer auth.mutex.Unlock()
	auth.publicKeys = make(map[string]*rsa.PublicKey)
	for id, value := range publicKeys {
		rsa, err := loadPublicKey([]byte(value))
		if err != nil {
			log.Warningf("failed to load RSA public key for %s: %s", id, err)
			continue
		}
		auth.publicKeys[id] = rsa
	}
}

func (auth *Auth) getRSAPublicKeys() map[string]*rsa.PublicKey {
	auth.mutex.RLock()
	defer auth.mutex.RUnlock()
	return auth.publicKeys
}

func (auth *Auth) setTokens(tokens map[string]string) {
	auth.tokens = tokens
}

func evaluate(expr string, paramMap map[string][]string, auth *Auth, credentials *ident.Credentials, verifier httpsig.Verifier) (result bool, err error) {
	log.Debugf("evaluating expr '%s' with params %v, auth %v, credentials %v", expr, paramMap, auth, credentials)
	// define builtins
	functions := map[string]eval.ExpressionFunction{
		// return true if call to URL returns HTTP status 200 ok
		// eg: allow(action, user, "sources/{sid}", "https://example.com/check")
		// action is one of HEAD (should we call this EXISTS?), CREATE, READ, UPDATE, DELETE
		"allow": func(args ...interface{}) (interface{}, error) {
			action, _ := args[0].(string)
			uid, _ := args[1].(string)
			rid, _ := args[2].(string)
			route, _ := args[3].(string)
			log.Debugf("checking user %s for access to resource '%s' at URL %s", uid, rid, route)

			body := []byte(fmt.Sprintf(`{ "action": "%s", "user": "%s", "resource": "%s"}`, action, uid, rid))
			token := config.MustGetConfig("ORIGIN_API_TOKEN")
			client := &http.Client{}
			req, err := http.NewRequest("POST", route, bytes.NewBuffer(body))
			if err != nil {
				return false, err
			}

			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := client.Do(req)
			if err != nil {
				return false, err
			}

			if resp.StatusCode != 200 {
				return false, fmt.Errorf(resp.Status)
			}

			return true, nil
		},
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
		// return the binding of a path or (TODO query parameter)
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
		// eg: role(tenantID('KPU'),'ADM','READ'),
		// role(tenantID('UVIC'),'DRAFT', 'PROGINFO','CREATE') etc
		"role": func(args ...interface{}) (interface{}, error) {

			tenantID, _ := args[0].(string)
			var (
				context  string
				category string
				action   string
			)
			if len(args) == 3 {
				context = ALL // default if not provided
				category = args[1].(string)
				action = args[2].(string)
			} else if len(args) == 4 {
				context = args[1].(string)
				category = args[2].(string)
				action = args[3].(string)
			} else {
				return false, fmt.Errorf("function role takes 3 or 4 arguments")
			}

			log.Debugf("calling role(%s,%s,%s)", tenantID, context, category, action)
			return auth.CheckJWT(credentials.JWT, tenantID, context, category, action), nil
		},
		// return true if identity has root permission
		"root": func(args ...interface{}) (interface{}, error) {
			log.Debug("calling root()")
			return auth.Root(credentials.JWT), nil
		},
		// return true if a request signed with tenant's private key is valid
		// with respect to tenant's public key
		"signature": func(args ...interface{}) (interface{}, error) {
			tenantID, _ := args[0].(string)
			log.Debugf("calling signature(%s)", tenantID)
			return verify(verifier, tenantID, auth.getRSAPublicKeys()), nil
		},
		// return the subdomain of the request
		"subdomain": func(args ...interface{}) (interface{}, error) {
			log.Debugf("calling subdomain()")
			return "TODO", nil
		},
		// return true if identity matches the user guid in path
		// eg: user(guid)
		"user": func(args ...interface{}) (interface{}, error) {
			guid, _ := args[0].(string)
			log.Debugf("calling user(%s)", guid)
			return strings.EqualFold(auth.User(credentials.JWT), guid), nil
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

func (auth *Auth) setMux(host string, mux *pat.HostMux) {
	auth.mutex.Lock()
	defer auth.mutex.Unlock()
	auth.hostMuxers[host] = mux
}

func (auth *Auth) getMux(host string) (mux *pat.HostMux, ok bool) {
	auth.mutex.RLock()
	defer auth.mutex.RUnlock()
	mux, ok = auth.hostMuxers[host]
	return mux, ok
}

func (auth *Auth) Blocked() (blocked []string) {
	for k := range auth.blocks {
		if auth.blocks[k] {
			blocked = append(blocked, k)
		}
	}
	return blocked
}

func (auth *Auth) Block(user string) {
	auth.blocks[user] = true
}

func (auth *Auth) Unblock(user string) {
	auth.blocks[user] = false
}

func (auth *Auth) Override(host string) string {
	return auth.overrides[host]
}

func (auth *Auth) RunMode() string {
	return auth.runMode
}

// Muxer returns the pattern mux for host
func (auth *Auth) Muxer(host string) (mux *pat.HostMux, err error) {
	var ok bool
	if mux, ok = auth.getMux(host); ok {
		return mux, nil
	}
	return mux, fmt.Errorf("host checks not defined for %s", host)
}

// HostChecks returns JSON formatted host checks
// func (auth *Auth) HostChecks() (hostChecksJSON string, err error) {
// 	data, err := json.Marshal(auth.HostChecks)
// 	if err != nil {
// 		return hostChecksJSON, err
// 	}
// 	return string(data), nil
// }

// UpdateFunc returns a function to update access system
func (auth *Auth) UpdateFunc() (f func(*AccessSystem) error) {
	return func(acs *AccessSystem) error {
		auth.setTokens(acs.Tokens)
		auth.setRSAPublicKeys(acs.PublicKeys)
		return auth.setAccess(acs.Checks, true)
	}
}

func loadPublicKey(keyData []byte) (*rsa.PublicKey, error) {
	pem, _ := pem.Decode(keyData)
	if pem == nil {
		return nil, fmt.Errorf("failed to decode public key %s", string(keyData))
	}
	if pem.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("public key is of the wrong type: %s", pem.Type)
	}

	key, err := x509.ParsePKIXPublicKey(pem.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(*rsa.PublicKey), nil
}
