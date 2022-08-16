package main

import (
	"flag"
	"fmt"
	"os"

	"bitbucket.org/_metalogic_/build"
	"bitbucket.org/_metalogic_/config"
	"bitbucket.org/_metalogic_/forward-auth/docs"
	"bitbucket.org/_metalogic_/forward-auth/stores/mssql"
	"bitbucket.org/_metalogic_/log"
)

var (
	info build.BuildInfo

	fileFlg  string
	levelFlg log.Level
)

func init() {
	flag.StringVar(&fileFlg, "file", "", "checks file")
	flag.Var(&levelFlg, "level", "set log level to one of debug, info, warning, error")

	var err error
	info = build.Info

	version := info.String()
	command := info.Name()

	flag.Usage = func() {
		fmt.Printf("Project %s:\n\n", version)
		fmt.Printf("Usage: %s -help (this message) | %s [options]:\n\n", command, command)
		flag.PrintDefaults()
	}

	docs.SwaggerInfo.Host = config.MustGetenv("APIS_HOST")
	projTemplate := config.MustGetConfig("OPENAPI_BUILD_TEMPLATE")
	version, err = info.Format(projTemplate)
	if err != nil {
		log.Warning("Failed to format openapi version from template %s: %s", projTemplate, err)
	} else {
		docs.SwaggerInfo.Description = fmt.Sprintf("%s%s", version, docs.SwaggerInfo.Description)
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

	loader, err := mssql.NewLoader()
	if err != nil {
		log.Fatal(err)
	}

	count, err := loader.Import(fileFlg)

	if err != nil {
		log.Fatalf("failed to load access control system to database from %s: %s", fileFlg, err)
	}

	log.Debugf("loaded %d host groups to database", count)

}
