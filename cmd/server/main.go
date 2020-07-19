package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/forward-auth/http"
	"bitbucket.org/_metalogic_/forward-auth/mssql"
	"bitbucket.org/_metalogic_/log"
	"gopkg.in/yaml.v2"
)

const (
	listenPort = ":8080"
	secretsDir = "/var/run/secrets/"
)

var (
	version string
	build   string

	auth  *fauth.Auth
	conf  Config
	rules []fauth.HostACLs

	configFlg  string
	disableFlg bool
	runMode    string
	storageFlg string
	levelFlg   log.Level

	env        string
	prefix     string
	dbname     string
	dbhost     string
	dbport     int
	dbuser     string
	dbpassword string

	jwtKey        []byte
	jwtRefreshKey []byte

	jwtHeader   string
	userHeader  string
	traceHeader string

	tenantParam string

	institutionEPBCIDs []string

	blockhosts []string

	// TODO: institution bearer tokens are hard-coded for now
	// when we get real multi-tenant access to the APIs this map should be populated from institutions-api
	// and should subscribe to changes to institutions-config
	// institution
	// application and institution bearer token names (token values are stored in Docker secrets named by $ENV_$TOKEN_NAME);
	institutionTokenNames = []string{"EPBC_API_TOKEN", "SFU_API_TOKEN", "SPUZZUM_API_TOKEN"}
	applicationTokenNames = []string{"APPL_TOKEN", "LCAT_TOKEN", "MGT_TOKEN", "SIGN_TOKEN", "STS_TOKEN"}

	// institutionTokens maps bearer tokens to the institution EPBC ID to which it is assigned
	// |  TOKEN  |  Institution EPBCID  |
	//
	// applicationTokens maps bearer tokens to the application token name that is authorized to use the token
	// |  TOKEN  |  Application Token Name  |
	//
	tokens = make(map[string]string)
)

func init() {

	// one of dev, tst, pvw, stg or prd
	env = config.MustGetenv("ENV")

	flag.StringVar(&configFlg, "config", "", "config file")
	flag.BoolVar(&disableFlg, "disable", false, "disable authorization")
	flag.Var(&levelFlg, "level", "set log level to one of debug, info, warning, error")

	prefix = config.IfGetenv("PREFIX", env)

	runMode = config.IfGetenv("RUN_MODE", "")
	// get config from Docker secrets or environment
	dbhost = config.MustGetenv("DB_HOST")
	dbport = config.MustGetInt("DB_PORT")
	dbname = config.MustGetenv("DB_NAME")
	dbuser = config.MustGetConfig("API_DB_USER")
	dbpassword = config.MustGetConfig("API_DB_PASSWORD")
	jwtKey = []byte(config.MustGetConfig("JWT_SECRET_KEY"))
	jwtRefreshKey = []byte(config.MustGetConfig("JWT_REFRESH_SECRET_KEY"))

	tenantParam = config.IfGetenv("TENANT_PARAM_NAME", ":tenantID")
	jwtHeader = config.IfGetenv("JWT_HEADER_NAME", "X-Jwt-Header")
	userHeader = config.IfGetenv("USER_HEADER_NAME", "X-User-Header")
	traceHeader = config.IfGetenv("TRACE_HEADER_NAME", "X-Trace-Header")

	// TODO load institution tokens from institutions-api (not Docker secrets)
	// for _, name := range institutionTokenNames {
	// 	v := config.MustGetConfig(name)
	// 	institutionTokens[v] = name
	// }

	// TODO: institution bearer tokens are hard-coded for now
	// when we get real multi-tenant access to the APIs this map should be populated from institutions-api
	// and should subscribe to changes to institutions-config

	// EPBC institution bearer auth is root equivalent - it's in Docker secrets EPBC_API_TOKEN (and in deprecated API_AUTH_TOKEN)
	//
	// Map institution bearer tokens to institution EPBC IDs

	conf = NewConfig()

	// the EPBC Institution token is treated as root equivalent in all rules
	tokens[config.MustGetConfig("EPBC_API_TOKEN")] = "EPBC"

	// Simon Fraser University test institution API token
	tokens[config.MustGetConfig("SFU_API_TOKEN")] = config.MustGetConfig("SFU_ID")

	// Spuzzum test institution API token
	tokens[config.MustGetConfig("SPUZZUM_API_TOKEN")] = config.MustGetConfig("SPUZZUM_ID")

	// TODO load the app token names from a config file
	for _, name := range applicationTokenNames {
		v := config.MustGetConfig(name)
		tokens[v] = name
	}

	flag.StringVar(&storageFlg, "storage", "MOCK", "the user storage type")

	flag.Usage = func() {
		fmt.Printf("Usage (forward-auth version %s, build %s):\n\n", version, build)
		fmt.Printf("forward-auth -help (this message) | forward-auth [options] RULES-FILE:\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	if levelFlg != log.None {
		log.SetLevel(levelFlg)
	} else {
		loglevel := os.Getenv("LOG_LEVEL")
		if loglevel == "DEBUG" {
			log.SetLevel(log.DebugLevel)
		}
	}

	if configFlg == "" {
		configFlg = config.IfGetenv("CONFIG_PATH", "./config.yaml:/usr/local/etc/forward-auth/config.yaml")
	}

	data, err := config.LoadFromSearchPath(configFlg)
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		log.Fatal(err)
	}

	tokens := make(map[string]string)
	for _, token := range append(conf.ApplicationTokens, conf.TenantTokens...) {
		tokens[token] = config.MustGetConfig(token)
	}

	for _, tenant := range conf.TenantIDs {
		conf.AddTenant(tenant, config.MustGetConfig(tenant))
	}

	auth := fauth.NewAuth(jwtKey)
	log.Debugf("config: %+v", conf)

	data, err = config.LoadFromSearchPath("./rules.json:/usr/local/etc/forward-auth/rules.json")
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(data, &rules)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("rules: %+v", rules)

	if disableFlg {
		runMode = "noAuth"
	}

	svc, err := mssql.New(prefix, append(applicationTokenNames, institutionTokenNames...), blockhosts, dbname, dbhost, dbport, dbuser, dbpassword, runMode)
	if err != nil {
		log.Fatalf("failed to create forward-auth Service: %s", err)
	}
	defer svc.Close()

	handler := http.NewHandler(svc, jwtHeader, userHeader, traceHeader)

	log.Fatal(handler.ServeHTTP(":8080"))

	// the allow hosts under forward-auth control handle their own authz
	/* 	allowMux := pat.NewHostMux(http.StatusOK)
	   	fauth.Hostchecks[platformString(prefix, "admin.educationplannerbc.ca")] = allowMux
	   	fauth.Hostchecks[platformString(prefix, "apply.educationplannerbc.ca")] = allowMux
	   	fauth.Hostchecks[platformString(prefix, "apply-admin.educationplannerbc.ca")] = allowMux
	   	fauth.Hostchecks[platformString(prefix, "mc.educationplannerbc.ca")] = allowMux
	   	fauth.Hostchecks[platformString(prefix, "oauth-demo.educationplannerbc.ca")] = allowMux
	   	fauth.Hostchecks[platformString(prefix, "signon.educationplannerbc.ca")] = allowMux
	   	fauth.Hostchecks[platformString(prefix, "sts-private.educationplannerbc.ca")] = allowMux

	   	// EPBC Servers for test institutions
	   	fauth.Hostchecks[platformString(prefix, "horsefly.educationplannerbc.ca")] = allowMux
	   	fauth.Hostchecks[platformString(prefix, "skookumchuck.educationplannerbc.ca")] = allowMux
	   	fauth.Hostchecks[platformString(prefix, "spuzzum.educationplannerbc.ca")] = allowMux

	   	var hostMux *pat.HostMux
	   	hostMux = apiMux(http.StatusOK)
	   	fauth.Hostchecks[platformString(prefix, "api.educationplannerbc.ca")] = hostMux
	   	fauth.Hostchecks[platformString(prefix, "api-private.educationplannerbc.ca")] = hostMux

	   	hostMux = apisMux(http.StatusForbidden)
	   	fauth.Hostchecks[platformString(prefix, "apis.educationplannerbc.ca")] = hostMux
	   	fauth.Hostchecks[platformString(prefix, "apis-private.educationplannerbc.ca")] = hostMux

	   	hostMux = logsMux(http.StatusForbidden)
	   	fauth.Hostchecks[platformString(prefix, "logs.educationplannerbc.ca")] = hostMux
	   	fauth.Hostchecks[platformString(prefix, "logs-private.educationplannerbc.ca")] = hostMux

	   	for k, v := range institutionTokens {
	   		institutionEPBCIDs = append(institutionEPBCIDs, v)
	   		log.Debugf("loaded institutionToken[%s]: %s", k, v)
	   	}

	   	for k, v := range applicationTokens {
	   		log.Debugf("loaded appTokens[%s]: %s", k, v)
	   	}

	   	for host, mux := range fauth.Hostchecks {
	   		log.Debugf("loaded host %s with muxer %+v", host, mux)
	   	}

	   	log.Fatal(route()) */
}

func platformString(prefix, name string) string {
	prefix = strings.ToLower(prefix)
	name = strings.ToLower(name)
	if name == "admin.educationplannerbc.ca" || name == "logs.educationplannerbc.ca" || prefix != "prd" {
		return prefix + "-" + name
	}
	return name
}
