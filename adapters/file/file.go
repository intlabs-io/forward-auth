package file

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	"bitbucket.org/_metalogic_/pat"
	"github.com/BurntSushi/toml"
)

// Service implements the forward-auth service interface against Microsoft SQLServer
type Service struct {
	prefix       string
	directory    string
	hostMuxers   map[string]*pat.HostMux
	overrides    map[string]int
	blockedUsers map[string]bool
	checks       fauth.Checks
	runMode      string
	lock         sync.RWMutex
	version      string
}

// New creates a new Service and sets the database
func New(prefix, jwtHeader, configPath, runMode, dir string) (svc *Service, err error) {
	svc = &Service{
		prefix:     prefix,
		overrides:  make(map[string]int),
		hostMuxers: make(map[string]*pat.HostMux),
		runMode:    runMode,
	}

	// load configuration from config path
	data, err := config.LoadFromSearchPath("file.toml", configPath)
	if err != nil {
		log.Fatal(err)
	}

	conf := NewConfig()
	err = toml.Unmarshal(data, &conf)
	if err != nil {
		log.Fatal(err)
	}

	var tokens = make(map[string]string)
	// add token mappings from token value to token name
	for _, token := range conf.Tokens {
		if token == conf.RootToken { // associate tenant token with token name "ROOT_TOKEN"
			tokens[config.MustGetConfig(token)] = "ROOT_TOKEN"
		} else {
			tokens[config.MustGetConfig(token)] = token
		}
	}

	// add token mappings from tenant token value to tenantID
	for _, t := range conf.Tenants {
		tenantID := t + "_ID"
		token := t + "_API_TOKEN"
		tokens[config.MustGetConfig(token)] = config.MustGetConfig(tenantID)
	}

	log.Debugf("config: %+v", conf)

	jwtKey := []byte(config.MustGetConfig("JWT_SECRET_KEY"))
	// TODO jwtRefreshKey := []byte(config.MustGetConfig("JWT_REFRESH_SECRET_KEY"))

	// block list of usernames, hostnames, IP addresses
	blocks := make(map[string]bool)
	auth := fauth.NewAuth(jwtKey, tokens, blocks)

	log.Debugf("configured authorization environment %+v", auth)

	// load checks from file
	data, err = config.LoadFromSearchPath("checks.json", ".:/usr/local/etc/forward-auth")
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(data, &svc.checks)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("rules: %+v", svc.checks)

	for _, host := range svc.checks.AllowHosts {
		svc.overrides[platformString(prefix, host)] = 1
	}

	for _, host := range svc.checks.DenyHosts {
		if svc.overrides[platformString(prefix, host)] == 1 {
			log.Errorf("deny override conflicts with allow override for %s; deny takes precedence", host)
		}
		svc.overrides[platformString(prefix, host)] = 2
	}

	for _, hostACL := range svc.checks.CheckHosts {
		// default to deny
		hostMux := pat.NewDenyMux()
		if hostACL.Default == "allow" {
			hostMux = pat.NewAllowMux()
		}
		for _, host := range hostACL.Hosts {
			if v, ok := svc.overrides[platformString(prefix, host)]; ok {
				log.Warningf("%d override host on %s disables defined host checks", v, platformString(prefix, host))
			}
			svc.hostMuxers[platformString(prefix, host)] = hostMux
			for _, acl := range hostACL.ACLs {
				pathPrefix := hostMux.AddPrefix(acl.Root, pat.DenyHandler)
				for _, path := range acl.Paths {
					if r, ok := path.Rules["GET"]; ok {
						pathPrefix.Get(path.Path, fauth.Handler(r, jwtHeader, auth))
						continue
					}
					if r, ok := path.Rules["POST"]; ok {
						pathPrefix.Post(path.Path, fauth.Handler(r, jwtHeader, auth))
						continue
					}
					if r, ok := path.Rules["PUT"]; ok {
						pathPrefix.Put(path.Path, fauth.Handler(r, jwtHeader, auth))
						continue
					}
					if r, ok := path.Rules["DELETE"]; ok {
						pathPrefix.Del(path.Path, fauth.Handler(r, jwtHeader, auth))
						continue
					}
					if r, ok := path.Rules["HEAD"]; ok {
						pathPrefix.Head(path.Path, fauth.Handler(r, jwtHeader, auth))
						continue
					}
				}
			}
		}
	}

	log.Debugf("initialized new file service %+v", svc)

	return svc, err
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

// Override overrides access control processing at the host level,
// returning 0 if no override, 1 if ALLOW override and 2 if DENY override
func (svc *Service) Override(host string) int {
	if v, ok := svc.overrides[host]; ok {
		return v
	}
	return 0
}

// Close closes the DB connection
func (svc *Service) Close() {
}

// Health checks to see if the DB is available.
func (svc *Service) Health() error {
	return nil
}

// Info return information about the Service.
func (svc *Service) Info() string {
	info := &info{}
	info.Hostname = os.Getenv("HOSTNAME")
	info.Directory = svc.directory
	info.LogLevel = log.GetLevel().String()
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return fmt.Sprintf("failed to marshal info from %+v", info)
	}
	return string(infoJSON)
}

// Muxer returns the pattern mux for host
func (svc *Service) Muxer(host string) (mux *pat.HostMux, err error) {
	var ok bool
	if mux, ok = svc.hostMuxers[host]; ok {
		return mux, nil
	}
	return mux, fmt.Errorf("host checks not defined for %s", host)
}

// Checks returns JSON formatted checks
func (svc *Service) Rules() (rulesJSON string, err error) {
	data, err := json.Marshal(svc.checks)
	if err != nil {
		return rulesJSON, err
	}
	return string(data), nil
}

// Stats returns Service  statistics
// TODO keep running stats of authorization request handling
func (svc *Service) Stats() string {
	js := fmt.Sprintf("{\"Requests\": %d, \"Allowed\" : %d, \"Denied\": %d}", 100, 50, 50)
	return js
}

// Version returns the database version
func (svc *Service) Version() string {
	return svc.version
}

func platformString(prefix, name string) string {
	prefix = strings.ToLower(prefix)
	name = strings.ToLower(name)
	if name == "admin.educationplannerbc.ca" || name == "logs.educationplannerbc.ca" || prefix != "prd" {
		return prefix + "-" + name
	}
	return name
}
