package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/forward-auth/build"
	"bitbucket.org/_metalogic_/forward-auth/docs"
	"bitbucket.org/_metalogic_/forward-auth/server"
	"bitbucket.org/_metalogic_/forward-auth/stores/file"
	"bitbucket.org/_metalogic_/forward-auth/stores/mssql"
	"bitbucket.org/_metalogic_/log"
)

var (
	info *build.ProjectInfo

	configFlg  string
	disableFlg bool
	runMode    string
	levelFlg   log.Level
	portFlg    string
	storageFlg string

	dbname     string
	dbhost     string
	dbport     int
	dbuser     string
	dbpassword string

	jwtHeader   string
	userHeader  string
	traceHeader string

	tenantParam string
)

func init() {

	flag.StringVar(&configFlg, "config", "", "config file")
	flag.BoolVar(&disableFlg, "disable", false, "disable authorization")
	flag.Var(&levelFlg, "level", "set log level to one of trace, debug, info, warning, error")
	flag.StringVar(&portFlg, "port", ":8080", "HTTP listen port")
	flag.StringVar(&storageFlg, "store", config.IfGetenv("FORWARD_AUTH_STORAGE", "file"), "storage adapter type - one of file, mssql, mock")

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

	docs.SwaggerInfo.Host = config.MustGetenv("APIS_HOST")
	projTemplate := config.IfGetenv("OPENAPI_PROJECT_TEMPLATE", "<pre>((Project))\n(branch ((Branch)), commit ((Commit)))\nbuilt at ((Built))</pre>\n\n")
	version, err = info.Format(projTemplate)
	if err != nil {
		log.Warning("failed to format openapi version from template %s: %s", projTemplate, err)
	} else {
		docs.SwaggerInfo.Description = fmt.Sprintf("%s%s", version, docs.SwaggerInfo.Description)
	}

}

func main() {
	flag.Parse()

	runMode = config.IfGetenv("RUN_MODE", "")
	// get config from Docker secrets or environment
	dbhost = config.MustGetenv("DB_HOST")
	dbport = config.MustGetInt("DB_PORT")
	dbname = config.MustGetenv("DB_NAME")
	dbuser = config.MustGetConfig("API_DB_USER")
	dbpassword = config.MustGetConfig("API_DB_PASSWORD")

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

	var store fauth.Store
	var err error
	switch storageFlg {
	case "file":
		store, err = file.New(configPath)
	case "mssql":
		store, err = mssql.New(jwtHeader, configPath, runMode, dbname, dbhost, dbport, dbuser, dbpassword)
	}

	if err != nil {
		log.Fatalf("failed to create forward-auth %s Service: %s", store.ID(), err)
	}
	defer store.Close()

	exitDone := &sync.WaitGroup{}
	exitDone.Add(2)

	authzSrv := server.Start(portFlg, runMode, tenantParam, userHeader, traceHeader, store, exitDone)

	log.Infof("forward-auth started with %s storage adapter", store.ID())

	// Wait for a SIGINT (perhaps triggered by user with CTRL-C) or SIGTERM (from Docker)
	// Run cleanup when signal is received
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Warning("forward-auth received stop signal - shutting down")

	// now close the servers gracefully ("shutdown")
	var ctx context.Context
	var cancel context.CancelFunc

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Warning("stopping forward-auth")
	authzSrv.Shutdown(ctx)

	// wait for goroutines started in StartEventServer() to stop
	exitDone.Wait()

	log.Warning("forward-auth shutdown complete - exiting")

}
