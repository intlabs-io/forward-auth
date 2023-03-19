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

	"bitbucket.org/_metalogic_/build"
	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/forward-auth/docs"
	"bitbucket.org/_metalogic_/forward-auth/server"
	"bitbucket.org/_metalogic_/forward-auth/stores/file"
	"bitbucket.org/_metalogic_/forward-auth/stores/mssql"
	"bitbucket.org/_metalogic_/forward-auth/stores/postgres"
	"bitbucket.org/_metalogic_/log"
)

var (
	info       build.BuildInfo
	configFlg  string
	disableFlg bool
	levelFlg   log.Level
	portFlg    string
	storageFlg string
)

func init() {

	flag.StringVar(&configFlg, "config", "", "path to file adapter config directory")
	flag.BoolVar(&disableFlg, "disable", false, "disable forward authorization")
	flag.Var(&levelFlg, "level", "set log level to one of trace, debug, info, warning, error")
	flag.StringVar(&portFlg, "port", ":8080", "HTTP listen port")
	flag.StringVar(&storageFlg, "store", config.IfGetenv("FORWARD_AUTH_STORAGE", "file"), "storage adapter type - one of file, mssql, mock")

	var err error
	info = build.Info

	version := info.String()
	command := info.Name()

	flag.Usage = func() {
		fmt.Printf("Project %s:\n\n", version)
		fmt.Printf("Usage: %s -help (this message) | %s [options]:\n\n", command, command)
		flag.PrintDefaults()
	}

	docs.SwaggerInfo.Host = config.IfGetenv("APIS_HOST", "localhost")
	projTemplate := config.IfGetenv("OPENAPI_BUILD_TEMPLATE", "<pre>((Project))\n(version ((Version)), revision ((Revision)))\n of ((Built))</pre>\n\n")

	version, err = info.Format(projTemplate)
	if err != nil {
		log.Warningf("Failed to format openapi version from template %s: %s", projTemplate, err)
	} else {
		docs.SwaggerInfo.Description = fmt.Sprintf("%s%s", version, docs.SwaggerInfo.Description)
	}

}

func main() {
	flag.Parse()

	runMode := config.IfGetenv("RUN_MODE", "")

	// - rootToken is the name of the tenant API token that is treated as ROOT
	// - tenantParam is the name of the tenant ID path parameter used in rule expressions
	// - jwtHeader is the name of the header in requests that carries a user JSON Web Token
	// - userHeader is the name of the header containing the user identifier extracted from the JWT
	// - traceHeader is the name of the header containing a trace identifier used for log coordination
	//   and returned by forward-auth; Traefik attaches the userHeader and traceHeader to the request
	//   for downstream consumption

	tenantParam := config.IfGetenv("TENANT_PARAM_NAME", ":tenantID")
	jwtHeader := config.IfGetenv("JWT_HEADER_NAME", "X-Jwt-Header")
	userHeader := config.IfGetenv("USER_HEADER_NAME", "X-User-Header")
	traceHeader := config.IfGetenv("TRACE_HEADER_NAME", "X-Trace-Header")

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

	dataDir := configFlg
	if dataDir == "" {
		dataDir = config.IfGetenv("FORWARD_AUTH_DATA_DIR", "/usr/local/etc/forward-auth")
	}

	var store fauth.Store
	var err error
	switch storageFlg {
	case "file":
		store, err = file.New(dataDir)
	case "mssql":
		store, err = mssql.New()
	case "postgres":
		store, err = postgres.New()
	}

	if err != nil {
		log.Fatalf("failed to create forward-auth %s service: %s", store.ID(), err)
	}
	defer store.Close()

	exitDone := &sync.WaitGroup{}
	exitDone.Add(2)

	authzSrv := server.Start(portFlg, runMode, tenantParam, jwtHeader, userHeader, traceHeader, store, exitDone)

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
