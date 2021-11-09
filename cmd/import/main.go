package main

import (
	"flag"
	"fmt"
	"os"

	"bitbucket.org/_metalogic_/config"
	"bitbucket.org/_metalogic_/forward-auth/store/mssql"
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
	dbhost = config.MustGetConfig("DB_HOST")
	dbport = config.MustGetInt("DB_PORT")
	dbname = config.MustGetConfig("DB_NAME")
	dbuser = config.MustGetConfig("API_DB_USER")
	dbpassword = config.MustGetConfig("API_DB_PASSWORD")

	flag.Usage = func() {
		fmt.Printf("Usage (load version %s, build %s):\n\n", version, build)
		fmt.Printf("load -help (this message) | load [options] RULES-FILE:\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	if fileFlg == "" {
		flag.Usage()
		os.Exit(1)
	}

	if levelFlg != log.None {
		log.SetLevel(levelFlg)
	} else {
		loglevel := os.Getenv("LOG_LEVEL")
		if loglevel == "DEBUG" {
			log.SetLevel(log.DebugLevel)
		}
	}

	loader, err := mssql.NewLoader(dbname, dbhost, dbport, dbuser, dbpassword)
	if err != nil {
		log.Fatal(err)
	}

	count, err := loader.Import(fileFlg)

	if err != nil {
		log.Fatalf("failed to import access controls from %s: %s", fileFlg, err)
	}

	log.Debugf("loaded %d host groups to database", count)

}
