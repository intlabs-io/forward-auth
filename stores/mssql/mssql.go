package mssql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"time"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http" // dot import fo avoid package prefix in reference (shutup lint)
	"bitbucket.org/_metalogic_/log"
	mssql "github.com/denisenkom/go-mssqldb"
	"github.com/fsnotify/fsnotify"
)

// MSSql implements the forward-auth store interface against Microsoft SQLServer
type MSSql struct {
	database     *sql.DB
	context      context.Context
	info         map[string]string
	applications string
	watcher      *fsnotify.Watcher
}

// New creates a new SQL Server storage service and sets the database
func New(dir, database, server string, port int, user, password string) (store *MSSql, err error) {
	// configure MSSql Server
	values := url.Values{}
	values.Set("database", database)
	values.Set("app", "forward-auth")
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(user, password),
		Host:   fmt.Sprintf("%s:%d", server, port),
		// Path:  instance, // if connecting to an instance instead of a port
		RawQuery: values.Encode(),
	}
	log.Debugf("sqlserver connection string: %s", u.Redacted())

	db, err := sql.Open("sqlserver", u.String())
	if err != nil {
		return store, err
	}
	db.SetConnMaxLifetime(300 * time.Second)
	db.SetMaxIdleConns(50)
	db.SetMaxOpenConns(50)

	info := make(map[string]string)
	info["Database"] = database
	info["Type"] = "sqlserver"
	info["Version"], err = store.getVersion()

	if err != nil {
		log.Error(err.Error())
	}
	store = &MSSql{
		database:     db,
		context:      context.TODO(),
		info:         info,
		applications: filepath.Join(dir, "applications.json"),
	}

	log.Debugf("initialized new mssql service %+v", store)

	return store, err
}

/*******************************
 implement the Store interface
********************************/

// ID returns the store ID
func (store *MSSql) ID() string {
	return "mssql"
}

func (store *MSSql) Close() error {
	return store.database.Close()
}

// Load loads an access control system from the database
func (store *MSSql) Load() (acs *fauth.AccessSystem, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.database.QueryContext(store.context, "[authz].[GetAccessControlSystem]")

	if err != nil {
		return acs, dbError(err)
	}
	defer rows.Close()

	var checksJSON string
	for rows.Next() {
		err = rows.Scan(&checksJSON)
	}
	if err != nil {
		log.Error(err.Error())
		return acs, NewDBError(err.Error())
	}

	checks := &fauth.HostChecks{}
	err = json.Unmarshal([]byte(checksJSON), checks)
	if err != nil {
		log.Error(err.Error())
		return acs, NewDBError(err.Error())
	}

	acs = &fauth.AccessSystem{
		Checks: checks,
	}
	return acs, nil
}

// Blocks returns the map of blocked users
// TODO this needs to come from the database
func (store *MSSql) Blocks() (map[string]bool, error) {
	return make(map[string]bool), nil
}

// Tokens returns a map of bearer token values to their names.
// Application tokens are defined in Docker secrets, while
// tenant tokens are defined in the database
func (store *MSSql) Tokens(rootToken string) (tokens map[string]string, err error) {
	// load applications from file
	data, err := ioutil.ReadFile(store.applications)
	if err != nil {
		return tokens, err
	}

	var applications []fauth.Application

	err = json.Unmarshal(data, applications)
	if err != nil {
		return tokens, err
	}

	log.Debugf("loaded applications from '%s': %+v", store.applications, applications)

	tokens = make(map[string]string)

	// load application bearer token mappings from token value to token name
	for _, application := range applications {
		if application.Bearer != nil && application.Bearer.Store == "docker" {
			tokens[config.MustGetConfig(application.Bearer.Name)] = application.Bearer.Name
		}
	}
	return tokens, nil
}

/*******************************
 implement the Common interface
********************************/

// Health checks to see if the DB is available.
func (store *MSSql) Health() error {
	return store.database.Ping()
}

// Info returns information about the Service.
func (store *MSSql) Info() (info map[string]string) {
	return store.info
}

// Stats returns Service  statistics
func (store *MSSql) Stats() string {
	dbstats := store.database.Stats()
	js := fmt.Sprintf("{\"MaxOpenConnections\": %d, \"OpenConnections\" : %d, \"InUse\": %d, \"Idle\": %d, \"WaitCount\": %d, \"WaitDuration\": %d, \"MaxIdleClosed\": %d, \"MaxLifetimeClosed\": %d}",
		dbstats.MaxOpenConnections,
		dbstats.OpenConnections,
		dbstats.InUse,
		dbstats.Idle,
		dbstats.WaitCount,
		dbstats.WaitDuration,
		dbstats.MaxIdleClosed,
		dbstats.MaxLifetimeClosed)
	return js
}

func (store *MSSql) getVersion() (version string, err error) {
	_, err = store.database.QueryContext(store.context, "[dbo].[Version]", sql.Named("Version", sql.Out{Dest: &(version)}))
	if err != nil {
		log.Errorf("%s", err)
		return version, err
	}
	return version, nil
}

func dbError(err error) error {
	if err == nil {
		return nil
	}
	dberr := err.(mssql.Error)
	code := dberr.SQLErrorNumber()
	code = code - 50000

	switch code {
	case 400:
		return NewBadRequestError(dberr.SQLErrorMessage())
	case 404:
		return NewNotFoundError(dberr.SQLErrorMessage())
	case 500:
		return NewServerError(fmt.Sprintf("%s: %s", dberr.SQLErrorServerName(), dberr.SQLErrorMessage()))
	default:
		return NewBadRequestError(dberr.SQLErrorMessage())
	}
}
