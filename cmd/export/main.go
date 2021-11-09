package main

import (
	"flag"
	"fmt"
	"os"

	"bitbucket.org/_metalogic_/config"
	"bitbucket.org/_metalogic_/forward-auth/store/file"
	"bitbucket.org/_metalogic_/forward-auth/store/mssql"
	"bitbucket.org/_metalogic_/log"
)

var (
	version string
	build   string

	fileFlg    string
	levelFlg   log.Level
	adapterFlg string

	dbname     string
	dbhost     string
	dbport     int
	dbuser     string
	dbpassword string
)

func init() {

	flag.StringVar(&adapterFlg, "adapter", "file", "adapter type - one of file, mssql, mock")
	flag.StringVar(&fileFlg, "file", "", "checks file")

	flag.Var(&levelFlg, "level", "set log level to one of debug, info, warning, error")

	flag.Usage = func() {
		fmt.Printf("Usage (dump version %s, build %s):\n\n", version, build)
		fmt.Printf("dump -help (this message) | dump [options] RULES-FILE:\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	if adapterFlg == "file" && fileFlg == "" {
		flag.Usage()
		log.Error("a checks file must be passed with file adapter")
		return
	}

	if levelFlg != log.None {
		log.SetLevel(levelFlg)
	} else {
		loglevel := os.Getenv("LOG_LEVEL")
		if loglevel == "DEBUG" {
			log.SetLevel(log.DebugLevel)
		}
	}

	switch adapterFlg {
	case "file":
		acs, err := file.AccessControls(fileFlg)
		if err != nil {
			log.Fatalf("failed to load access controls from file: %s", err)
		}
		fmt.Printf("%+v\n", acs)

	case "mssql":
		// get config from Docker secrets or environment
		dbhost = config.MustGetenv("DB_HOST")
		dbport = config.MustGetInt("DB_PORT")
		dbname = config.MustGetenv("DB_NAME")
		dbuser = config.MustGetConfig("API_DB_USER")
		dbpassword = config.MustGetConfig("API_DB_PASSWORD")

		acs, err := mssql.AccessControls(dbname, dbhost, dbport, dbuser, dbpassword)
		if err != nil {
			log.Fatalf("failed to load access controls from mssql: %s", err)
		}
		fmt.Printf("%+v\n", acs)
	}

}
