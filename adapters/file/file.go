package file

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	"bitbucket.org/_metalogic_/pat"
	"github.com/BurntSushi/toml"
)

// Service implements the forward-auth service interface
type Service struct {
	directory    string
	auth         *fauth.Auth
	muxLock      sync.RWMutex
	hostMuxers   map[string]*pat.HostMux
	overrides    map[string]string
	blockedUsers map[string]bool
	runMode      string
	lock         sync.RWMutex
	info         map[string]string
}

// Config holds the configuration read from a config file
// - JWTHeader is the name of the header in requests that carries a user JSON Web Token
// - UserHeader is the name of the header containing the user identifier extracted from the JWT
//   and returned by forward-auth; Traefik attaches UserHeader to the request for downstream consumption
// - RootToken is the name of the tenant API token that is treated as ROOT
// - Tokens is a list of token names to be looked up in the environment or in secrets
// - Tenants is a list of tenant names to be looked up in the environment or in secrets
type Config struct {
	JWTHeader  string   `toml:"jwtHeader"`
	UserHeader string   `toml:"userHeader"`
	RootToken  string   `toml:"rootToken"`
	Tokens     []string `toml:"Tokens"`
	Tenants    []string `toml:"Tenants"`
}

// New creates a new forward-auth Service from file
func New(configPath, runMode string) (svc *Service, err error) {
	svc = &Service{
		directory:  configPath,
		runMode:    runMode,
		hostMuxers: make(map[string]*pat.HostMux),
	}

	conf, err := LoadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}

	var tokens = make(map[string]string)
	// tokens maps bearer tokens to token names that are used to express conditions in access rules; the map contains
	//   mappings of tokens to tenant IDs and application names:
	//   |  TOKEN  |  Institution EPBCID  (the institution EPBC ID to which the token is assigned)
	//   |  TOKEN  |  Application Token Name  | (the application token name that is authorized to use the token)
	//
	// add token mappings from token value to token name
	for _, token := range conf.Tokens {
		if token == conf.RootToken { // associate tenant token with token name "ROOT_TOKEN"
			tokens[config.MustGetConfig(token)] = "ROOT_TOKEN"
		} else {
			tokens[config.MustGetConfig(token)] = token
		}
	}

	svc.info = make(map[string]string)
	svc.info["type"] = "file"
	svc.info["hostname"] = os.Getenv("HOSTNAME")
	svc.info["directory"] = svc.directory

	// TODO: institution bearer tokens are hard-coded for now
	// when we get real multi-tenant access to the APIs this map should be populated from institutions-api
	// and should subscribe to changes to institutions-config
	// application and institution bearer token names (token values are stored in Docker secrets named by $ENV_$TOKEN_NAME);
	//
	// add token mappings from tenant token value to tenantID
	for _, t := range conf.Tenants {
		tenantID := t + "_ID"
		token := t + "_API_TOKEN"
		tokens[config.MustGetConfig(token)] = config.MustGetConfig(tenantID)
	}

	jwtKey := []byte(config.MustGetConfig("JWT_SECRET_KEY"))
	// TODO jwtRefreshKey := []byte(config.MustGetConfig("JWT_REFRESH_SECRET_KEY"))

	// block list of usernames, hostnames, IP addresses
	blocks := make(map[string]bool)

	svc.auth = fauth.NewAuth(conf.JWTHeader, jwtKey, tokens, blocks)

	log.Debugf("configured authorization environment %+v", svc.auth)

	err = svc.LoadAccess(false)
	if err != nil {
		return svc, err
	}

	log.Debugf("initialized new file service %+v", svc)

	return svc, err
}

// LoadConfig reads configuration from file
func LoadConfig(configPath string) (conf Config, err error) {
	file := filepath.Join(configPath, "file.toml")
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return conf, err
	}
	err = toml.Unmarshal(data, &conf)
	if err != nil {
		return conf, err
	}
	jwtHeader := config.IfGetenv("JWT_HEADER_NAME", "X-Jwt-Header")
	if conf.JWTHeader == "" {
		conf.JWTHeader = jwtHeader
	}
	log.Debugf("loaded config from '%s': %+v", file, conf)
	return conf, nil
}

// LoadAccess loads checks from a JSON checks file
func (svc *Service) LoadAccess(reload bool) (err error) {
	file := filepath.Join(svc.directory, "checks.json")

	// load checks from file
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	var access fauth.AccessControls
	err = json.Unmarshal(data, &access)
	if err != nil {
		return err
	}

	log.Debugf("loaded checks from '%s': %+v", file, access)

	svc.overrides = access.Overrides

	// create Pat Host Muxers from Checks
	for _, hostCheck := range access.HostChecks {
		// default to deny
		hostMux := pat.NewDenyMux()
		if hostCheck.Default == "allow" {
			hostMux = pat.NewAllowMux()
		}
		// each host shares the hostMux
		for _, host := range hostCheck.Hosts {
			if v, ok := svc.overrides[host]; ok {
				log.Warningf("%s override on host %s disables defined host checks", v, host)
			}
			if _, ok := svc.getMux(host); !reload && ok {
				log.Errorf("ignoring duplicate host checks for %s", host)
				continue
			}
			svc.setMux(host, hostMux)
		}
		// add path prefixes to hostMux
		for _, check := range hostCheck.Checks {
			pathPrefix := hostMux.AddPrefix(check.Base, pat.DenyHandler)
			for _, path := range check.Paths {
				if r, ok := path.Rules["GET"]; ok {
					pathPrefix.Get(path.Path, fauth.Handler(r, svc.auth))
				}
				if r, ok := path.Rules["POST"]; ok {
					pathPrefix.Post(path.Path, fauth.Handler(r, svc.auth))
				}
				if r, ok := path.Rules["PUT"]; ok {
					pathPrefix.Put(path.Path, fauth.Handler(r, svc.auth))
				}
				if r, ok := path.Rules["DELETE"]; ok {
					pathPrefix.Del(path.Path, fauth.Handler(r, svc.auth))
				}
				if r, ok := path.Rules["HEAD"]; ok {
					pathPrefix.Head(path.Path, fauth.Handler(r, svc.auth))
				}
			}
		}
	}

	log.Debugf("loaded checks: %+v", access)

	return nil
}

func (svc *Service) setMux(host string, mux *pat.HostMux) {
	svc.muxLock.Lock()
	defer svc.muxLock.Unlock()
	svc.hostMuxers[host] = mux
}

func (svc *Service) getMux(host string) (mux *pat.HostMux, ok bool) {
	svc.muxLock.RLock()
	defer svc.muxLock.RUnlock()
	mux, ok = svc.hostMuxers[host]
	return mux, ok
}

// AccessControls loads checks from a JSON checks file
func AccessControls(file string) (acs fauth.AccessControls, err error) {

	// load checks from file
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return acs, err
	}

	err = json.Unmarshal(data, &acs)
	if err != nil {
		return acs, err
	}

	log.Debugf("loaded checks: %+v", acs)

	return acs, nil
}

// Block adds userID to the user block access list
// TODO protect with mutex
func (svc *Service) Block(userID string) {
	svc.blockedUsers[userID] = true

}

// Unblock removes userID from the user block access list
// TODO protect with mutex
func (svc *Service) Unblock(userID string) {
	delete(svc.blockedUsers, userID)
}

// Blocked returns the user block access list
func (svc *Service) Blocked() []string {
	var blocks []string
	for b := range svc.blockedUsers {
		blocks = append(blocks, b)
	}
	return blocks
}

// Override returns the configured access override (allow or deny) for a given host, or "none" if none is configured
func (svc *Service) Override(host string) string {
	if v, ok := svc.overrides[host]; ok {
		return v
	}
	return "none"
}

// Close closes the source checks file
func (svc *Service) Close() {
}

// Health checks to see if the file service is available.
func (svc *Service) Health() error {
	return nil
}

// Info return information about the Service.
func (svc *Service) Info() map[string]string {
	return svc.info
}

// Muxer returns the pattern mux for host
func (svc *Service) Muxer(host string) (mux *pat.HostMux, err error) {
	var ok bool
	if mux, ok = svc.getMux(host); ok {
		return mux, nil
	}
	return mux, fmt.Errorf("host checks not defined for %s", host)
}

// HostChecks returns JSON formatted host checks
func (svc *Service) HostChecks() (hostChecksJSON string, err error) {
	data, err := json.Marshal(svc.HostChecks)
	if err != nil {
		return hostChecksJSON, err
	}
	return string(data), nil
}

// Stats returns Service  statistics
// TODO keep running stats of authorization request handling
func (svc *Service) Stats() string {
	js := fmt.Sprintf("{\"Requests\": %d, \"Allowed\" : %d, \"Denied\": %d}", 100, 50, 50)
	return js
}
