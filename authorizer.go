package fauth

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	acc "bitbucket.org/_metalogic_/access-apis"

	"bitbucket.org/_metalogic_/config"
	"bitbucket.org/_metalogic_/eval"
	"bitbucket.org/_metalogic_/genstr"
	"bitbucket.org/_metalogic_/httpsig"
	"bitbucket.org/_metalogic_/ident"
	"bitbucket.org/_metalogic_/log"
	"bitbucket.org/_metalogic_/pat"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const (
	// ANY wildcard category matches any individual category (eg FINANCE, CONTENT, IMAGE, etc)
	ANY = "ANY"
	// ALL wildcard action matches any of CREATE, READ, UPDATE, DELETE, EXISTS; also used for all contexts
	ALL = "ALL"
)

// Action constants as defined in database table auth.ACTIONS
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
//   - keyFunc is a function passed to JWT parse function to return the key for decrypting the JWT token
//   - owner is the owner of the current forward-auth deployment
//   - sessions is a map of session IDs to session objects containing user JWT tokens
//   - publicKeys maps key names to their rsa.PublicKey value
//   - tokens maps token values passed in a request to token names referenced in
//     access control functions; eg: bearer(ROOT_KEY) returns true if the bearer
//     auth token in the request maps to the token name ROOT_KEY
//   - blocks is a map of subjects (usernames, hostnames, IP addresses) to be denied
//     access; subject names must be unique for all subjects
//
// an instance of Auth is passed to handlers to drive authorization calculations
type Auth struct {
	runMode      string
	rootOverride bool
	sessionMode  string
	sessionName  string
	jwtHeader    string
	keyFunc      func(token *jwt.Token) (interface{}, error)
	owner        Owner
	sessions     map[string]session
	publicKeys   map[string]*rsa.PublicKey
	tokens       map[string]string
	blocks       map[string]bool
	overrides    map[string]string
	mutex        sync.RWMutex
	hostMuxers   map[string]*pat.HostMux
}

type session struct {
	auth         *acc.Auth
	uid          string // the uid of the session user
	jwtToken     string
	refreshToken string
	expiry       int64 // the expiry time in Unix seconds of the JWT
}

func (s session) Auth() *acc.Auth {
	return s.auth
}

func (s session) UID() string {
	return s.uid
}

func (s *session) JWT() string {
	return s.jwtToken
}

func (s *session) RefreshJWT() string {
	return s.refreshToken
}

func (s *session) IsExpired() bool {
	return time.Unix(s.expiry, 0).Before(time.Now())
}

// NewAuth returns a new RSA Auth
func NewAuth(acs *AccessSystem, rootOverride bool, sessionMode, sessionName, jwtHeader string, publicKey, secret []byte) (auth *Auth, err error) {
	auth = &Auth{
		rootOverride: rootOverride,
		sessionMode:  sessionMode,
		sessionName:  sessionName,
		jwtHeader:    jwtHeader,
		sessions:     make(map[string]session),
		hostMuxers:   make(map[string]*pat.HostMux),
		owner:        acs.Owner,
		publicKeys:   make(map[string]*rsa.PublicKey),
		tokens:       acs.Tokens,
		blocks:       acs.Blocks,
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

func (auth *Auth) CreateSession(a *acc.Auth, reset bool) (id string, expiresAt time.Time) {
	if reset {
		id = genstr.Number(6)
	} else {
		id = uuid.New().String()
	}
	auth.sessions[id] = session{
		auth:         a,
		uid:          *a.Identity.UID,
		jwtToken:     a.JWT,
		refreshToken: a.JwtRefresh,
		expiry:       a.ExpiresAt,
	}
	return id, time.Unix(a.ExpiresAt, 0)
}

func (auth *Auth) UpdateSession(id string, a *acc.Auth) (expiresAt time.Time) {
	auth.sessions[id] = session{
		uid:          *a.Identity.UID,
		jwtToken:     a.JWT,
		refreshToken: a.JwtRefresh,
		expiry:       a.ExpiresAt,
	}
	return time.Unix(a.ExpiresAt, 0)
}

func (auth *Auth) Sessions() (sessionsJSON string) {
	sessions := make([]string, 0)
	for id, sess := range auth.sessions {
		if !sess.IsExpired() {
			sessions = append(sessions, id)
		}
	}
	data, _ := json.Marshal(sessions)
	return string(data)
}

func (auth *Auth) Session(id string) (s session, err error) {
	s, ok := auth.sessions[id]
	if !ok {
		return s, fmt.Errorf("session not found for session id %s", id)
	}
	return s, nil
}

func (auth *Auth) DeleteSession(id string) {
	delete(auth.sessions, id)
}

// CheckBearerAuth checks for token in list of tokens returning true if found
func (auth *Auth) CheckBearerAuth(token string, tokens ...string) bool {
	for _, t := range tokens {
		if t == auth.tokens[token] {
			log.Debugf("allowing by bearer token '%s'", redact(token))
			return true
		}
	}
	log.Debugf("rejecting token '%s' by bearer auth for accepted tokens: %v", redact(token), tokens)
	return false
}

// CheckJWT returns true if jwt has action permission on category in the tenantID
func (auth *Auth) CheckJWT(jwt, context, action, category string) (allow bool) {
	if jwt == "" {
		return false
	}

	var err error
	var identity *Identity
	if identity, err = jwtIdentity(jwt, auth); err != nil {
		log.Errorf("JWT found in request is invalid: %s", err)
		return false
	}

	log.Debugf("identity found in JWT: %+v", *identity)

	// superuser only applies in the tenant of the user
	if identity.Superuser {
		if identity.TID != nil && *identity.TID == auth.owner.UID {
			return true
		}
	}

	log.Debugf("evaluating user permissions: %+v", identity.UserPermissions)

	// example:
	// [
	//	{Context:1b7c3bed-8472-4a54-9058-4154d345abf8 Permissions:[{Category:CONTENT Actions:[READ]} {Category:MEDIA Actions:[ANNOTATE READ]}]},
	//  {Context:5273d8a1-6bbd-4ccd-9bda-8340acb8cfe9 Permissions:[{Category:CONTENT Actions:[ALL]} {Category:MEDIA Actions:[ALL]}]},
	//  {Context:ccd660fc-5680-44b2-a570-17cf8229f694 Permissions:[{Category:ANY Actions:[ALL]}]}
	// ]
	for _, up := range identity.UserPermissions {
		log.Debugf("evaluating permission context %s against %s", up.Context, context)
		if up.Context == ALL || up.Context == context {
			for _, perm := range up.Permissions {
				log.Debugf("evaluating permission category %s against category %s", perm.Category, category)
				if perm.Category == ANY || perm.Category == category {
					for _, a := range perm.Actions {
						log.Debugf("evaluating permission action %s against action %s", a, action)
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

// Superuser returns true if jwt has superuser privilege
func (auth *Auth) Superuser(jwt string) bool {
	if jwt == "" {
		log.Debugf("empty JWT in request")
		return false
	}

	var err error
	var identity *Identity
	if identity, err = jwtIdentity(jwt, auth); err != nil {
		log.Errorf("JWT found in request is invalid: %s", err)
		return false
	}

	log.Debugf("identity found in JWT: %+v", *identity)

	// superuser only applies in the tenant of the user
	if identity.Superuser {
		if identity.TID != nil && *identity.TID == auth.owner.UID {
			return true
		}
	}

	return false
}

// Classification returns the user classication object
func (auth *Auth) Classification(jwt string) *Classification {
	if jwt == "" {
		return nil
	}

	var err error
	var identity *Identity
	if identity, err = jwtIdentity(jwt, auth); err != nil {
		log.Errorf("JWT found in request is invalid: %s", err)
		return nil
	}

	log.Debugf("identity found in JWT: %+v", *identity)

	return identity.Classification
}

// Identify returns the Identity found in jwt
func (auth *Auth) Identity(jwt string) error {
	if jwt == "" {
		return fmt.Errorf("empty JWT")
	}

	identity, err := jwtIdentity(jwt, auth)
	if err != nil {
		return fmt.Errorf("JWT is invalid: %s", err)
	}

	if identity == nil {
		return fmt.Errorf("no identity found in JWT: %s", jwt)
	}

	if identity.TID == nil {
		return fmt.Errorf("tenant ID in JWT cannot be nil")
	}

	if *identity.TID != auth.owner.UID {
		return fmt.Errorf("tenant ID (%s) in JWT does not match owner (%s)", *identity.TID, auth.owner.UID)
	}

	log.Debugf("identity found in JWT: %+v", *identity)

	return nil
}

// User returns the user UID in jwt
func (auth *Auth) User(jwt string) (uid string) {
	if jwt == "" {
		return uid
	}

	var err error
	var identity *Identity
	if identity, err = jwtIdentity(jwt, auth); err != nil {
		log.Errorf("JWT found in request is invalid: %s", err)
		return uid
	}

	if identity == nil {
		log.Errorf("no identity found in JWT: %s", jwt)
		return uid
	}

	log.Debugf("identity found in JWT: %+v", *identity)

	return *identity.UID
}

type EmailRequest struct {
	Email string `json:"email"`
}

// User type
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

// [{"permissions":{"context": "5273d8a1-6bbd-4ccd-9bda-8340acb8cfe9", "permissions": [{"actions": ["ALL"], "categoryCode": "CONTENT"}, {"actions": ["ALL"], "categoryCode": "MEDIA"}]}}]

// Permission type
type Permission struct {
	Category string   `json:"categoryCode"`
	Actions  []string `json:"actions"`
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

	if log.Loggable(log.DebugLevel) {

		m, err := json.Marshal(claims)
		if err != nil {
			log.Errorf("failed to marshal claims: %+v", claims)
		} else {
			log.Debugf("parsed JWT Claims: %s", m)
		}
	}

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
	mustAuth := rule.MustAuth

	if !mustAuth {
		if rule.Expression == "true" {
			return pat.AllowHandler
		}
		if rule.Expression == "false" {
			return pat.DenyHandler
		}
	}

	return func(method, path string, params map[string][]string, header http.Header) (status int, message, username string) {
		log.Debugf("running handler on %s: %s", method, path)

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

		var jwt string
		if mustAuth {
			log.Debugf("MustAuth rule requires valid user session")
			id, err := getSessionID(header, auth.sessionMode, auth.sessionName)
			if err != nil {
				jwt = header.Get(auth.jwtHeader)
				if jwt == "" {
					return http.StatusUnauthorized, "rule requires authentication but no session cookie or raw JWT token is present in request header", username
				}
			}

			log.Debugf("using session id %s", id)

			sess, ok := auth.sessions[id]
			if !ok {
				log.Debugf("rule requires authentication but there is no session with id %s, %s", id, username)
				return http.StatusUnauthorized, "rule requires authentication but there is no session with id " + id, username
			}

			if sess.IsExpired() {
				log.Debugf("rule requires authentication but session %s is expired %s", id, time.Unix(sess.expiry, 0).Format("2006-01-02 15:04:05"))
				return http.StatusUnauthorized, "rule requires authentication but session is expired", username
			}

			log.Debugf("using active session %+v", sess)

			jwt = sess.JWT()
			log.Debugf("setting JWT from session: %s", jwt)

			if err := auth.Identity(jwt); err != nil {
				return http.StatusUnauthorized, fmt.Sprintf("rule requires authentication but JWT contains invalid identity: %s", err), username
			}
		} else {
			jwt = header.Get(auth.jwtHeader)
			log.Debugf("setting JWT from request header: %s", jwt)
		}

		// credentials carry the bearer token and JWT if present
		credentials := &ident.Credentials{
			Token: token,
			JWT:   jwt,
		}

		if jwt != "" {
			username = auth.User(jwt)
			log.Debugf("setting user from JWT: %s", username)
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
	if checks == nil {
		log.Warning("empty host checks for auth")
		return nil
	}
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
			key := config.MustGetConfig("ROOT_KEY")
			client := &http.Client{}
			req, err := http.NewRequest("POST", route, bytes.NewBuffer(body))
			if err != nil {
				return false, err
			}

			req.Header.Set("Authorization", "Bearer "+key)
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
		// eg: bearer('ROOT_KEY', 'MC_APP_KEY' ...)
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
		"classification": func(args ...interface{}) (interface{}, error) {
			log.Debug("calling classification()")
			return auth.Classification(credentials.JWT), nil
		},
		// return the result of concatenating each argument;
		// arguments may be string literals or calls to other built-ins
		// eg: concat(param(':tenantID'), '-', param(':userID'))
		"concat": func(args ...interface{}) (interface{}, error) {
			var parts []string

			for _, arg := range args {
				parts = append(parts, arg.(string))
			}

			return strings.Join(parts, ""), nil
		},
		// return the binding of a path or query parameter
		// eg: param(':tenantID'), param('summary')
		"param": func(args ...interface{}) (interface{}, error) {
			param := args[0].(string)
			log.Debugf("calling param(%s)", param)
			if v, ok := paramMap[param]; ok {
				return v[0], nil
			}
			return "", nil
		},
		// return true if identity has role permission in tenant
		// eg: role('INSTITUTION','CREATE'),
		// role(param(':context'), 'CONTENT','CREATE') etc
		"role": func(args ...interface{}) (interface{}, error) {
			var (
				context  string
				action   string
				category string
			)
			if len(args) == 2 {
				context = ALL // default if not provided
				action = args[0].(string)
				category = args[1].(string)
			} else if len(args) == 3 {
				context = args[0].(string)
				action = args[1].(string)
				category = args[2].(string)
			} else {
				return false, fmt.Errorf("function role takes 2 or 3 arguments")
			}

			log.Debugf("calling role(%s,%s,%s)", context, action, category)
			return auth.CheckJWT(credentials.JWT, context, action, category), nil
		},
		// return true if identity has root permission
		"root": func(args ...interface{}) (interface{}, error) {
			log.Debug("calling Superuser()")
			return auth.Superuser(credentials.JWT), nil
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
		// return true if identity matches the user UUID in path
		// eg: user(param(':uuid'))
		"user": func(args ...interface{}) (interface{}, error) {
			uuid, _ := args[0].(string)
			log.Debugf("calling user(%s)", uuid)
			return strings.EqualFold(auth.User(credentials.JWT), uuid), nil
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

func (auth *Auth) RootOverride() bool {
	return auth.rootOverride
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
