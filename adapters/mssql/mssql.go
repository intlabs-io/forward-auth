package mssql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http" // dot import fo avoid package prefix in reference (shutup lint)
	"bitbucket.org/_metalogic_/log"
	"bitbucket.org/_metalogic_/pat"
	_ "github.com/denisenkom/go-mssqldb"
	mssql "github.com/denisenkom/go-mssqldb"
	"gopkg.in/yaml.v2"
)

// Service implements the forward-auth service interface against Microsoft SQLServer
type Service struct {
	database     *sql.DB
	context      context.Context
	auth         *fauth.Auth
	hostMuxers   map[string]*pat.HostMux
	overrides    map[string]string
	blockedUsers map[string]bool
	hostChecks   []fauth.HostChecks
	runMode      string
	lock         sync.RWMutex
	info         map[string]string
}

// New creates a new Service and sets the database
func New(jwtHeader, configPath, runMode string, database, server string, port int, user, password string) (svc *Service, err error) {
	svc = &Service{
		hostMuxers: make(map[string]*pat.HostMux),
		overrides:  make(map[string]string),
		context:    context.TODO(),
		runMode:    runMode}

	// load configuration from config path
	data, err := config.LoadFromSearchPath("mssql.yaml", configPath)
	if err != nil {
		log.Fatal(err)
	}

	conf := NewConfig()
	err = yaml.Unmarshal(data, &conf)
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

	publicKey, err := config.GetRawSecret("IDENTITY_PROVIDER_PUBLIC_KEY")
	if err != nil {
		return svc, err
	}

	secretKey := []byte(config.MustGetConfig("JWT_SECRET_KEY"))
	// TODO jwtRefreshKey := []byte(config.MustGetConfig("JWT_REFRESH_SECRET_KEY"))

	// block list of usernames, hostnames, IP addresses
	blocks := make(map[string]bool)

	svc.auth, err = fauth.NewAuth(jwtHeader, publicKey, secretKey, tokens, blocks)
	if err != nil {
		return svc, err
	}

	log.Debugf("configured authorization environment %+v", svc.auth)

	data, err = config.LoadFromSearchPath("rules.json", ".:/usr/local/etc/forward-auth")
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(data, &svc.hostChecks)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("rules: %+v", svc.hostChecks)

	// configure MSSql Server
	values := url.Values{}
	values.Set("database", database)
	values.Set("app", "EPBC applications-api")
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(user, password),
		Host:   fmt.Sprintf("%s:%d", server, port),
		// Path:  instance, // if connecting to an instance instead of a port
		RawQuery: values.Encode(),
	}
	log.Debugf("sqlserver connection string: %s", u.String())
	svc.database, err = sql.Open("sqlserver", u.String())
	if err != nil {
		return svc, err
	}

	svc.info = make(map[string]string)
	svc.info["Type"] = "sqlserver"
	svc.info["Version"], err = svc.getVersion()
	if err != nil {
		log.Error(err.Error())
	}
	svc.info["Database"] = database

	svc.database.SetConnMaxLifetime(300 * time.Second)
	svc.database.SetMaxIdleConns(50)
	svc.database.SetMaxOpenConns(50)

	//
	// TODO - convert file based rules to database
	//
	err = json.Unmarshal(data, &svc.hostChecks)
	if err != nil {
		log.Fatal(err)
	}
	for _, hostCheck := range svc.hostChecks {
		// FIXME: change NewHostMux to accept hostACL.Default bool not HTTP status
		hostMux := pat.NewHostMux(403)
		for _, host := range hostCheck.Hosts {
			svc.hostMuxers[host] = hostMux
			for _, check := range hostCheck.Checks {
				pathPrefix := hostMux.AddPrefix(check.Base, pat.DenyHandler)
				for _, path := range check.Paths {
					if r, ok := path.Rules["GET"]; ok {
						pathPrefix.Get(path.Path, fauth.Handler(r, svc.auth))
						continue
					}
					if r, ok := path.Rules["POST"]; ok {
						pathPrefix.Post(path.Path, fauth.Handler(r, svc.auth))
						continue
					}
					if r, ok := path.Rules["PUT"]; ok {
						pathPrefix.Put(path.Path, fauth.Handler(r, svc.auth))
						continue
					}
					if r, ok := path.Rules["DELETE"]; ok {
						pathPrefix.Del(path.Path, fauth.Handler(r, svc.auth))
						continue
					}
					if r, ok := path.Rules["HEAD"]; ok {
						pathPrefix.Head(path.Path, fauth.Handler(r, svc.auth))
						continue
					}
				}
			}
		}
	}

	log.Debugf("initialized new mssql service %+v", svc)

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

// AccessControls loads checks from a JSON checks file
func AccessControls(database, server string, port int, user, password string) (acs fauth.AccessControls, err error) {
	var (
		rows *sql.Rows
	)
	// configure MSSql Server
	values := url.Values{}
	values.Set("database", database)
	values.Set("app", "EPBC applications-api")
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(user, password),
		Host:   fmt.Sprintf("%s:%d", server, port),
		// Path:  instance, // if connecting to an instance instead of a port
		RawQuery: values.Encode(),
	}
	log.Debugf("sqlserver connection string: %s", u.String())

	db, err := sql.Open("sqlserver", u.String())
	if err != nil {
		return acs, err
	}

	rows, err = db.QueryContext(context.Background(), "[auth].[HostChecks]")

	if err != nil {
		return acs, err
	}

	defer rows.Close()

	var acsJSON string
	for rows.Next() {
		err = rows.Scan(&acsJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return acs, err
	}

	err = json.Unmarshal([]byte(acsJSON), &acs)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("loaded access controls: %+v", acs)

	return acs, nil
}

// Override overrides access control processing at the host level,
// returning 0 if no override, 1 if ALLOW override and 2 if DENY override
func (svc *Service) Override(host string) string {
	if v, ok := svc.overrides[host]; ok {
		return v
	}
	return "none"
}

// Muxer returns the pattern mux for host
func (svc *Service) Muxer(host string) (mux *pat.HostMux, err error) {
	var ok bool
	if mux, ok = svc.hostMuxers[host]; ok {
		return mux, nil
	}
	return mux, fmt.Errorf("host checks not defined for %s", host)
}

// Close closes the DB connection
func (svc *Service) Close() {
	svc.database.Close()
}

// Health checks to see if the DB is available.
func (svc *Service) Health() error {
	return svc.database.Ping()
}

// HostChecks returns JSON formatted host checks
func (svc *Service) HostChecks() (hostCheckJSON string, err error) {
	data, err := json.Marshal(svc.hostChecks)
	if err != nil {
		return hostCheckJSON, err
	}
	return string(data), nil
}

// Info returns information about the Service.
func (svc *Service) Info() (info map[string]string) {
	return svc.info
}

// Stats returns Service  statistics
func (svc *Service) Stats() string {
	dbstats := svc.database.Stats()
	js := fmt.Sprintf("{\"MaxOpenConnections\": %d, \"OpenConnections\" : %d, \"InUse\": %d, \"Idle\": %d, \"WaitCount\": %d, \"WaitDuration\": %d, \"MaxIdleClosed\": %d, \"MaxLifetimeClosed\": %d}",
		dbstats.MaxOpenConnections,
		dbstats.OpenConnections,
		dbstats.InUse,
		dbstats.Idle,
		dbstats.WaitCount,
		dbstats.WaitDuration,
		dbstats.MaxIdleClosed,
		dbstats.MaxLifetimeClosed)
	return js
}

func (svc *Service) getVersion() (version string, err error) {
	_, err = svc.database.QueryContext(svc.context, "[dbo].[Version]", sql.Named("Version", sql.Out{Dest: &(version)}))
	if err != nil {
		log.Errorf("%s", err)
		return version, err
	}
	return version, nil
}

func dbError(err error) error {
	if err == nil {
		return nil
	}
	dberr := err.(mssql.Error)
	code := dberr.SQLErrorNumber()
	code = code - 50000

	switch code {
	case 400:
		return NewBadRequestError(dberr.SQLErrorMessage())
	case 404:
		return NewNotFoundError(dberr.SQLErrorMessage())
	case 500:
		return NewServerError(fmt.Sprintf("%s: %s", dberr.SQLErrorServerName(), dberr.SQLErrorMessage()))
	default:
		return NewBadRequestError(dberr.SQLErrorMessage())
	}
}
