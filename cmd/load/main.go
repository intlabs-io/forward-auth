package main

import (
	"flag"
	"fmt"
	"os"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/forward-auth/adapters/file"
	"bitbucket.org/_metalogic_/forward-auth/adapters/mssql"
	"bitbucket.org/_metalogic_/log"
)

var (
	version string
	build   string

	rules []fauth.HostChecks

	configFlg  string
	disableFlg bool
	storageFlg string
	levelFlg   log.Level

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
)

func init() {

	flag.StringVar(&configFlg, "config", "", "config file")
	flag.BoolVar(&disableFlg, "disable", false, "disable authorization")
	flag.Var(&levelFlg, "level", "set log level to one of debug, info, warning, error")

	// get config from Docker secrets or environment
	dbhost = config.MustGetenv("DB_HOST")
	dbport = config.MustGetInt("DB_PORT")
	dbname = config.MustGetenv("DB_NAME")
	dbuser = config.MustGetConfig("API_DB_USER")
	dbpassword = config.MustGetConfig("API_DB_PASSWORD")

	flag.Usage = func() {
		fmt.Printf("Usage (load version %s, build %s):\n\n", version, build)
		fmt.Printf("load -help (this message) | forward-auth [options] RULES-FILE:\n\n")
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

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	var configPath = configFlg

	if configPath == "" {
		configPath = config.IfGetenv("CONFIG_PATH", cwd+":/usr/local/etc/forward-auth")
	}
	acs, err := file.AccessControls(configPath)
	if err != nil {
		log.Fatalf("failed to load checks from file: %s", err)
	}

	loader, err := mssql.NewLoader(dbname, dbhost, dbport, dbuser, dbpassword)
	if err != nil {
		log.Fatal(err)
	}

	count, err := loader.Load(acs)

	if err != nil {
		log.Fatalf("failed to load checks to database: %s", err)
	}

	log.Debugf("loaded %d checks to database", count)

}
