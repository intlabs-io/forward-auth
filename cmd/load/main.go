package main

import (
	"flag"
	"fmt"
	"os"

	"bitbucket.org/_metalogic_/config"
	"bitbucket.org/_metalogic_/forward-auth/adapters/file"
	"bitbucket.org/_metalogic_/forward-auth/adapters/mssql"
	"bitbucket.org/_metalogic_/log"
)

var (
	version string
	build   string

	fileFlg    string
	disableFlg bool
	levelFlg   log.Level

	dbname     string
	dbhost     string
	dbport     int
	dbuser     string
	dbpassword string
)

func init() {
	flag.StringVar(&fileFlg, "file", "", "checks file")
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

	acs, err := file.AccessControls(fileFlg)
	if err != nil {
		log.Fatalf("failed to load checks from file: %s", err)
	}

	loader, err := mssql.NewLoader(dbname, dbhost, dbport, dbuser, dbpassword)
	if err != nil {
		log.Fatal(err)
	}

	count, err := loader.Load(acs)

	if err != nil {
		log.Fatalf("failed to load checks file %s to database: %s", fileFlg, err)
	}

	log.Debugf("loaded %d checks to database", count)

}
