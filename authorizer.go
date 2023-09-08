package fauth

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	authn "bitbucket.org/_metalogic_/authenticate"

	"bitbucket.org/_metalogic_/config"
	"bitbucket.org/_metalogic_/eval"
	"bitbucket.org/_metalogic_/genstr"
	"bitbucket.org/_metalogic_/httpsig"
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
//   - owner is the owner of the current forward-auth deployment; if forward-auth is configured
//     to use auth9.net for user authentication, the value of owner must agree with the tenant configured
//     in auth9.net
//   - runMode if set to "TEST" causes forward-auth to return its access decision in the body
//     of a 4xx response; this prevents Traefik from forwarding requests that are otherwise authorized
//     to the backend for processing
//   - rootOverride is set to true causes forward-auth to authorize any request with accompanying root
//     bearer token
//   - sessionMode controls how session is sent with a requests (one of COOKIE or HEADER)
//   - sessionName the name of the session in the request (either cookie name or header name, respectively)
//   - jwtHeader is the name of the header containing the user's JWT
//   - keyFunc is a function passed to JWT parse function to return the key for decrypting the JWT token
//   - sessions is a map of app IDs to app session mappings (mapping a session ID to a session object);
//     session objects encapsulate user identity, JWT tokens and expiry time
//   - publicKeys maps key names to their rsa.PublicKey value
//   - tokens maps token values passed in a request to token names referenced in
//     access control functions; eg: bearer(ROOT_KEY) returns true if the bearer token
//     in the request maps to the token name ROOT_KEY
//   - blocks is a map of subjects (usernames, hostnames, IP addresses) to be denied
//     access without further evaluation; subject names must be unique for all subjects within an app
//   - hostMuxers TODO TODO
//   - mutext is used to handle concurrent access to auth
//
// an instance of Auth is passed to handlers to drive authorization calculations
type Auth struct {
	owner        Owner
	runMode      string
	rootOverride bool
	sessionMode  string
	sessionName  string
	jwtHeader    string
	keyFunc      func(token *jwt.Token) (interface{}, error)
	sessions     map[string]map[string]Session // app => app sessions
	publicKeys   map[string]*rsa.PublicKey
	tokens       map[string]string
	blocks       map[string]bool
	overrides    map[string]string
	hostMuxers   map[string]*pat.HostMux
	mutex        sync.RWMutex
}

// NewAuth returns a new RSA Auth
func NewAuth(acs *AccessSystem, rootOverride bool, sessionMode, sessionName, jwtHeader string, publicKey, secret []byte) (auth *Auth, err error) {
	auth = &Auth{
		rootOverride: rootOverride,
		sessionMode:  sessionMode,
		sessionName:  sessionName,
		jwtHeader:    jwtHeader,
		sessions:     make(map[string]map[string]Session),
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

func (auth *Auth) CreateSession(token, jwtToken, refreshToken string, expiry int64, reset bool) (id string, expiresAt time.Time) {
	app, ok := auth.tokens[token]
	if !ok {
		return id, time.Time{}
	}

	if reset {
		id = genstr.Number(6)
	} else {
		id = uuid.New().String()
	}

	identity, err := authn.FromJWT(jwtToken, auth.keyFunc)
	if err != nil {
		slog.Error("failed get identity from auth", "error", err)
		return id, time.Time{}
	}

	slog.Debug("creating session", "app", app, "id", id, "user", identity.UserID)

	if _, ok := auth.sessions[app]; !ok {
		auth.sessions[app] = make(map[string]Session)
	}

	auth.sessions[app][id] = Session{
		UserID:     identity.UserID,
		JWTToken:   jwtToken,
		JWTRefresh: refreshToken,
		Expiry:     expiry,
	}

	return id, time.Unix(expiry, 0)
}

// TODO return error if app session and id not found
func (auth *Auth) UpdateSession(id string, token, jwtToken, refreshToken string, expiry int64) (expiresAt time.Time) {
	app, ok := auth.tokens[token]
	if !ok {
		return time.Time{}
	}

	sessions, ok := auth.sessions[app]
	if !ok {
		return time.Time{}
	}

	identity, err := authn.FromJWT(jwtToken, auth.keyFunc)
	if err != nil {
		slog.Error("failed get identity from auth", "error", err)
		return time.Time{}
	}

	sessions[id] = Session{
		UserID:     identity.UserID,
		JWTToken:   jwtToken,
		JWTRefresh: refreshToken,
		Expiry:     expiry,
	}
	return time.Unix(expiry, 0)
}

func (auth *Auth) Sessions(token string) (sessionsJSON string) {

	app, ok := auth.tokens[token]
	if !ok {
		return sessionsJSON
	}

	sessions, ok := auth.sessions[app]
	if !ok {
		return sessionsJSON
	}

	list := make([]string, 0)
	for id, sess := range sessions {
		if !sess.IsExpired() {
			list = append(list, id)
		}
	}
	data, _ := json.Marshal(list)
	return string(data)
}

func (auth *Auth) Session(token, id string) (s Session, err error) {
	app, ok := auth.tokens[token]
	if !ok {
		return s, fmt.Errorf("session requires a valid client bearer token")
	}

	sessions, ok := auth.sessions[app]
	if !ok {
		return s, fmt.Errorf("app sessions not found for %s", app)
	}

	s, ok = sessions[id]
	if !ok {
		return s, fmt.Errorf("session not found for session id %s", id)
	}
	return s, nil
}

func (auth *Auth) DeleteSession(token, id string) {
	app, ok := auth.tokens[token]
	if !ok {
		return
	}

	sessions, ok := auth.sessions[app]
	if !ok {
		return
	}

	delete(sessions, id)
}

// CheckBearerAuth checks for token in list of tokens returning true if found
func (auth *Auth) CheckBearerAuth(token string, tokens ...string) bool {
	for _, t := range tokens {
		if t == auth.tokens[token] {
			slog.Debug("allowing by bearer token", "token", redact(token))
			return true
		}
	}
	slog.Debug(fmt.Sprintf("rejecting token '%s' by bearer auth for accepted tokens: %v", redact(token), tokens))
	return false
}

// CheckJWT returns true if jwt has action permission on category in the tenantID
func (auth *Auth) CheckJWT(jwt, context, action, category string) (allow bool) {
	if jwt == "" {
		return false
	}

	var err error
	var identity *authn.Identity
	if identity, err = authn.FromJWT(jwt, auth.keyFunc); err != nil {
		slog.Error("failed to parse identity from JWT in request", "error", err)
		return false
	}

	slog.Debug(fmt.Sprintf("identity found in JWT: %+v", *identity))

	// superuser only applies in the tenant of the user
	if identity.Superuser {
		if identity.TenantID == auth.owner.UID {
			return true
		}
	}

	slog.Debug(fmt.Sprintf("evaluating user permissions: %+v", identity.Permissions))

	// example:
	// [
	//	{Context:1b7c3bed-8472-4a54-9058-4154d345abf8 Permissions:[{Category:CONTENT Actions:[READ]} {Category:MEDIA Actions:[ANNOTATE READ]}]},
	//  {Context:5273d8a1-6bbd-4ccd-9bda-8340acb8cfe9 Permissions:[{Category:CONTENT Actions:[ALL]} {Category:MEDIA Actions:[ALL]}]},
	//  {Context:ccd660fc-5680-44b2-a570-17cf8229f694 Permissions:[{Category:ANY Actions:[ALL]}]}
	// ]
	for _, up := range identity.Permissions {
		slog.Debug(fmt.Sprintf("evaluating permission context %s against %s", up.Context, context))
		if up.Context == ALL || up.Context == context {
			// slog.Debugf("evaluating permission category %s against category %s", perm.Category, category)
			actions := up.CategoryActions[ANY]
			actions = append(actions, up.CategoryActions[category]...)
			for _, a := range actions {
				slog.Debug(fmt.Sprintf("evaluating permission action %s against action %s", a, action))
				if a == ALL || a == action {
					return true
				}
			}
		}
	}

	return false
}

func (auth *Auth) JWTIdentity(tknStr string) (identity *authn.Identity, err error) {
	return authn.FromJWT(tknStr, auth.keyFunc)
}

// Superuser returns true if jwt has superuser privilege
func (auth *Auth) Superuser(jwt string) bool {
	if jwt == "" {
		slog.Debug("empty JWT in request")
		return false
	}

	var err error
	var identity *authn.Identity
	if identity, err = authn.FromJWT(jwt, auth.keyFunc); err != nil {
		slog.Error("JWT found in request is invalid", "error", err)
		return false
	}

	slog.Debug(fmt.Sprintf("identity found in JWT: %+v", *identity))

	// superuser only applies in the tenant of the user
	if identity.Superuser {
		if identity.TenantID == auth.owner.UID {
			return true
		}
	}

	return false
}

// Classification returns the user classication object
func (auth *Auth) Classification(jwt string) *authn.Classification {
	if jwt == "" {
		return nil
	}

	var err error
	var identity *authn.Identity
	if identity, err = authn.FromJWT(jwt, auth.keyFunc); err != nil {
		slog.Error("JWT found in request is invalid", "error", err)
		return nil
	}

	slog.Debug(fmt.Sprintf("identity found in JWT: %+v", *identity))

	return identity.Classification
}

// Identify returns the CheckIdentity found in jwt
func (auth *Auth) CheckIdentity(jwt string) error {
	if jwt == "" {
		return fmt.Errorf("empty JWT")
	}

	identity, err := authn.FromJWT(jwt, auth.keyFunc)
	if err != nil {
		return fmt.Errorf("JWT is invalid: %s", err)
	}

	if identity == nil {
		return fmt.Errorf("no identity found in JWT: %s", jwt)
	}

	if identity.TenantID == "" {
		return fmt.Errorf("tenant ID in identity cannot be nil")
	}

	if identity.TenantID != auth.owner.UID {
		return fmt.Errorf("tenant ID (%s) in identity does not match owner (%s)", identity.TenantID, auth.owner.UID)
	}

	slog.Debug(fmt.Sprintf("identity found in JWT: %+v", *identity))

	return nil
}

// UserID returns the user UID of identity found jwt
func (auth *Auth) UserID(jwt string) (uid string) {
	if jwt == "" {
		return uid
	}

	var err error
	var identity *authn.Identity
	if identity, err = authn.FromJWT(jwt, auth.keyFunc); err != nil {
		slog.Error("JWT found in request is invalid", "error", err)
		return uid
	}

	if identity == nil {
		slog.Error("no identity found in JWT", "jwt", jwt)
		return uid
	}

	slog.Debug(fmt.Sprintf("identity found in JWT: %+v", *identity))

	return identity.UserID
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
		slog.Debug(fmt.Sprintf("running handler on %s: %s", method, path))

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
			app, ok := auth.tokens[token]
			if !ok {
				return http.StatusUnauthorized, "MustAuth requires an app client session but none present", username
			}

			id, err := getSessionID(header, auth.sessionMode, auth.sessionName)
			if err != nil {
				jwt = header.Get(auth.jwtHeader)
				if jwt == "" {
					return http.StatusUnauthorized, "rule requires authentication but no session cookie or raw JWT token is present in request header", username
				}
			}

			slog.Debug(fmt.Sprintf("using session id %s", id))

			sess, ok := auth.sessions[app][id]
			if !ok {
				slog.Debug(fmt.Sprintf("rule requires authentication but there is no session with id %s, %s", id, username))
				return http.StatusUnauthorized, "rule requires authentication but there is no session with id " + id, username
			}

			if sess.IsExpired() {
				slog.Debug(fmt.Sprintf("rule requires authentication but session %s is expired %s", id, time.Unix(sess.Expiry, 0).Format("2006-01-02 15:04:05")))
				return http.StatusUnauthorized, "rule requires authentication but session is expired", username
			}

			slog.Debug(fmt.Sprintf("using active session %+v", sess))

			jwt = sess.JWTToken
			slog.Debug(fmt.Sprintf("setting JWT from session: %s", jwt))

			if err := auth.CheckIdentity(jwt); err != nil {
				return http.StatusUnauthorized, fmt.Sprintf("rule requires authentication but JWT contains invalid identity: %s", err), username
			}
		} else {
			jwt = header.Get(auth.jwtHeader)
			slog.Debug(fmt.Sprintf("setting JWT from request header: %s", jwt))
		}

		// credentials carry the bearer token and JWT if present
		credentials := &authn.Credentials{
			Token: token,
			JWT:   jwt,
		}

		if jwt != "" {
			username = auth.UserID(jwt)
			slog.Debug(fmt.Sprintf("setting user from JWT: %s", username))
		}

		u, err := url.Parse(path)
		if err != nil { // shouldn't happen
			slog.Error(err.Error())
			return http.StatusForbidden, message, username
		}

		// get signature verifier
		var verifier httpsig.Verifier
		if header.Get(string(httpsig.Signature)) != "" {
			verifier, err = httpsig.NewForwardAuthVerifier(header, method, path, u.RawQuery)
			if err != nil {
				slog.Warn(fmt.Sprintf("found signature header but failed to get verifier: %s", err))
			}
		}

		if t, err := evaluate(rule.Expression, params, auth, credentials, verifier); err != nil {
			message := fmt.Sprintf("%s %s failed evaluation for rule %s: %s", method, path, rule.Expression, err)
			slog.Error(message)
			return http.StatusForbidden, message, username
		} else if t {
			message := fmt.Sprintf("%s %s allowed by rule %s", method, path, rule.Expression)
			slog.Debug(message)
			return http.StatusOK, message, username
		} else {
			message := fmt.Sprintf("%s %s denied by rule %s", method, path, rule.Expression)
			slog.Debug(message)
			return http.StatusForbidden, message, username
		}
	}
}

func (auth *Auth) setAccess(checks *HostChecks, refresh bool) error {
	if checks == nil {
		slog.Warn("empty host checks for auth")
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
				slog.Warn(fmt.Sprintf("%s override on host %s disables defined host checks", v, host))
			}
			if _, ok := auth.getMux(host); !refresh && ok {
				slog.Warn(fmt.Sprintf("ignoring duplicate host checks for %s", host))
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
			slog.Warn(fmt.Sprintf("failed to load RSA public key for %s: %s", id, err))
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

func evaluate(expr string, paramMap map[string][]string, auth *Auth, credentials *authn.Credentials, verifier httpsig.Verifier) (result bool, err error) {
	slog.Debug(fmt.Sprintf("evaluating expr '%s' with params %v, auth %v, credentials %v", expr, paramMap, auth, credentials))
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
			slog.Debug(fmt.Sprintf("checking user %s for access to resource '%s' at URL %s", uid, rid, route))

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
			slog.Debug(fmt.Sprintf("calling bearer(%v)", tokens))
			return auth.CheckBearerAuth(credentials.Token, tokens...), nil
		},
		"classification": func(args ...interface{}) (interface{}, error) {
			slog.Debug("calling classification()")
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
			slog.Debug(fmt.Sprintf("calling param(%s)", param))
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

			slog.Debug(fmt.Sprintf("calling role(%s,%s,%s)", context, action, category))
			return auth.CheckJWT(credentials.JWT, context, action, category), nil
		},
		// return true if identity has root permission
		"root": func(args ...interface{}) (interface{}, error) {
			slog.Debug("calling Superuser()")
			return auth.Superuser(credentials.JWT), nil
		},
		// return true if a request signed with tenant's private key is valid
		// with respect to tenant's public key
		"signature": func(args ...interface{}) (interface{}, error) {
			tenantID, _ := args[0].(string)
			slog.Debug(fmt.Sprintf("calling signature(%s)", tenantID))
			return verify(verifier, tenantID, auth.getRSAPublicKeys()), nil
		},
		// return the subdomain of the request
		"subdomain": func(args ...interface{}) (interface{}, error) {
			slog.Debug(fmt.Sprintf("calling subdomain()"))
			return "TODO", nil
		},
		// return true if identity matches the user UUID in path
		// eg: user(param(':uuid'))
		"user": func(args ...interface{}) (interface{}, error) {
			uuid, _ := args[0].(string)
			slog.Debug(fmt.Sprintf("calling user(%s)", uuid))
			return strings.EqualFold(auth.UserID(credentials.JWT), uuid), nil
		},
	}

	expression, err := eval.NewEvaluableExpressionWithFunctions(expr, functions)
	if err != nil {
		slog.Error(err.Error())
		return result, err
	}

	parameters := make(map[string]interface{}, 8)
	for k, v := range paramMap {
		parameters[k] = v
	}

	slog.Debug(fmt.Sprintf("evaluating expression %s", expr))
	val, err := expression.Evaluate(parameters)
	if err != nil {
		slog.Error(err.Error())
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

func Bearer(req *http.Request) (token string) {
	// Request Headers
	authHeader := req.Header.Get("Authorization")

	if authHeader != "" {
		// Get the Bearer auth token
		splitToken := strings.Split(authHeader, "Bearer ")
		if len(splitToken) == 2 {
			token = splitToken[1]
			strings.TrimSpace(token)
		}
	}
	return token
}
