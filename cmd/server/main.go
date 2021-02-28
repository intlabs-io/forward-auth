package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/forward-auth/adapters/file"
	"bitbucket.org/_metalogic_/forward-auth/adapters/mssql"
	"bitbucket.org/_metalogic_/forward-auth/build"
	"bitbucket.org/_metalogic_/forward-auth/http"
	"bitbucket.org/_metalogic_/log"
	"github.com/fsnotify/fsnotify"
)

var (
	info *build.ProjectInfo

	rules []fauth.HostChecks

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
)

func init() {

	flag.StringVar(&adapterFlg, "adapter", "file", "adapter type - one of file, mssql, mock")
	flag.StringVar(&configFlg, "config", "", "config file")
	flag.BoolVar(&disableFlg, "disable", false, "disable authorization")
	flag.Var(&levelFlg, "level", "set log level to one of debug, info, warning, error")

	flag.StringVar(&storageFlg, "storage", "MOCK", "the user storage type")

	var err error
	info, err = build.Info()
	if err != nil {
		log.Fatalf("get project info failed: %s", err)
	}

	version := info.String()
	command := info.Name()

	flag.Usage = func() {
		fmt.Printf("Project %s:\n\n", version)
		fmt.Printf("Usage: %s -help (this message) | %s [options]:\n\n", command, command)
		flag.PrintDefaults()
	}

}

func main() {
	flag.Parse()

	// one of dev, tst, pvw, stg or prd
	env = config.MustGetenv("ENV")

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

	if levelFlg == log.None {
		loglevel := os.Getenv("LOG_LEVEL")
		if loglevel == "DEBUG" {
			log.SetLevel(log.DebugLevel)
		}
	} else {
		log.SetLevel(levelFlg)
	}

	if disableFlg {
		runMode = "noAuth"
	}

	var configPath = configFlg
	if configPath == "" {
		configPath = config.IfGetenv("CONFIG_PATH", "/usr/local/etc/forward-auth")
	}

	checksFile := filepath.Join(configPath, "checks.json")

	var handler *http.Handler
	switch adapterFlg {
	case "file":
		svc, err := file.New(configPath, runMode)

		if err != nil {
			log.Fatalf("failed to create forward-auth Service: %s", err)
		}
		defer svc.Close()

		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}
		defer watcher.Close()

		go func() {
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return
					}
					log.Debugf("checks file watch: %s", event)
					if event.Name == checksFile && (event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write) {
						log.Infof("checks file %s has changed; reloading", checksFile)
						svc.LoadAccess(true)
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						return
					}
					log.Error(err)
				}
			}
		}()

		err = watcher.Add(configPath)
		if err != nil {
			log.Fatal(err)
		}

		handler = http.NewHandler(svc, userHeader, traceHeader)
	case "mssql":
		svc, err := mssql.New(jwtHeader, configPath, runMode, dbname, dbhost, dbport, dbuser, dbpassword)

		if err != nil {
			log.Fatalf("failed to create forward-auth Service: %s", err)
		}
		defer svc.Close()

		handler = http.NewHandler(svc, userHeader, traceHeader)
	}

	log.Fatal(handler.ServeHTTP(":8080"))

}
