package main

import (
	"flag"
	"fmt"
	"os"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/forward-auth/adapters/file"
	"bitbucket.org/_metalogic_/forward-auth/adapters/mssql"
	"bitbucket.org/_metalogic_/forward-auth/http"
	"bitbucket.org/_metalogic_/log"
)

const (
	listenPort = ":8080"
	secretsDir = "/var/run/secrets/"
)

var (
	version string
	build   string

	rules []fauth.HostACLs

	configFlg  string
	disableFlg bool
	runMode    string
	storageFlg string
	levelFlg   log.Level
	adapterFlg string

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

	blocks map[string]bool

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

	flag.StringVar(&adapterFlg, "adapter", "file", "adapter type - one of file, mssql, mock")
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

	// the EPBC Institution token is treated as root equivalent in all rules
	tokens[config.MustGetConfig("EPBC_API_TOKEN")] = "ROOT_TOKEN"

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

	if disableFlg {
		runMode = "noAuth"
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	var configPath = configFlg
	var handler *http.Handler
	switch adapterFlg {
	case "file":
		if configPath == "" {
			configPath = config.IfGetenv("CONFIG_PATH", cwd+":/usr/local/etc/forward-auth")
		}
		var dir = ""
		svc, err := file.New(prefix, jwtHeader, configPath, runMode, dir)

		if err != nil {
			log.Fatalf("failed to create forward-auth Service: %s", err)
		}
		defer svc.Close()

		handler = http.NewHandler(svc, jwtHeader, userHeader, traceHeader)
	case "mssql":
		if configPath == "" {
			configPath = config.IfGetenv("CONFIG_PATH", cwd+":/usr/local/etc/forward-auth")
		}
		svc, err := mssql.New(prefix, jwtHeader, configPath, runMode, dbname, dbhost, dbport, dbuser, dbpassword)

		if err != nil {
			log.Fatalf("failed to create forward-auth Service: %s", err)
		}
		defer svc.Close()

		handler = http.NewHandler(svc, jwtHeader, userHeader, traceHeader)
	}

	log.Fatal(handler.ServeHTTP(":8080"))

}
