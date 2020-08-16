package file

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	"bitbucket.org/_metalogic_/pat"
	"github.com/BurntSushi/toml"
)

// Service implements the forward-auth service interface against Microsoft SQLServer
type Service struct {
	directory    string
	hostMuxers   map[string]*pat.HostMux
	overrides    map[string]string
	blockedUsers map[string]bool
	access       fauth.AccessControls
	runMode      string
	lock         sync.RWMutex
	version      string
}

// New creates a new forward-auth Service from file
func New(jwtHeader, configPath, runMode string) (svc *Service, err error) {
	svc = &Service{
		overrides:  make(map[string]string),
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

	svc.access, err = AccessControls(configPath)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("loaded checks: %+v", svc.access)

	svc.overrides = svc.access.Overrides

	// create Pat Host Muxers from Checks
	for _, hostCheck := range svc.access.HostChecks {
		// default to deny
		hostMux := pat.NewDenyMux()
		if hostCheck.Default == "allow" {
			hostMux = pat.NewAllowMux()
		}
		// each host shares the hostMux
		for _, host := range hostCheck.Hosts {
			if v, ok := svc.overrides[host]; ok {
				log.Warningf("%d override on host %s disables defined host checks", v, host)
			}
			if _, ok := svc.hostMuxers[host]; ok {
				log.Errorf("ignoring duplicate host checks for %s", host)
				continue
			}
			svc.hostMuxers[host] = hostMux
		}
		// add path prefixes to hostMux
		for _, check := range hostCheck.Checks {
			pathPrefix := hostMux.AddPrefix(check.Base, pat.DenyHandler)
			for _, path := range check.Paths {
				if r, ok := path.Rules["GET"]; ok {
					pathPrefix.Get(path.Path, fauth.Handler(r, jwtHeader, auth))
				}
				if r, ok := path.Rules["POST"]; ok {
					pathPrefix.Post(path.Path, fauth.Handler(r, jwtHeader, auth))
				}
				if r, ok := path.Rules["PUT"]; ok {
					pathPrefix.Put(path.Path, fauth.Handler(r, jwtHeader, auth))
				}
				if r, ok := path.Rules["DELETE"]; ok {
					pathPrefix.Del(path.Path, fauth.Handler(r, jwtHeader, auth))
				}
				if r, ok := path.Rules["HEAD"]; ok {
					pathPrefix.Head(path.Path, fauth.Handler(r, jwtHeader, auth))
				}
			}
		}
	}

	log.Debugf("initialized new file service %+v", svc)

	return svc, err
}

// AccessControls loads checks from a JSON checks file
func AccessControls(configPath string) (checks fauth.AccessControls, err error) {

	// load checks from file
	data, err := config.LoadFromSearchPath("checks.json", ".:/usr/local/etc/forward-auth")
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(data, &checks)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("loaded checks: %+v", checks)

	return checks, nil
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

// Override overrides access control processing at the host level
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

// HostChecks returns JSON formatted host checks
func (svc *Service) HostChecks() (hostChecksJSON string, err error) {
	data, err := json.Marshal(svc.access)
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

// Version returns the database version
func (svc *Service) Version() string {
	return svc.version
}
