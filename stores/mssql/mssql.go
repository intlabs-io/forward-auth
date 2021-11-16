package mssql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http" // dot import fo avoid package prefix in reference (shutup lint)
	"bitbucket.org/_metalogic_/log"
	mssql "github.com/denisenkom/go-mssqldb"
)

// MSSql implements the forward-auth database interface against Microsoft SQLServer
type MSSql struct {
	database *sql.DB
	context  context.Context
	info     map[string]string
}

// New creates a new Service and sets the database
func New(jwtHeader, configPath, runMode string, database, server string, port int, user, password string) (store *MSSql, err error) {
	store = &MSSql{
		context: context.TODO(),
	}
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
	store.database, err = sql.Open("sqlserver", u.String())
	if err != nil {
		return store, err
	}

	store.info = make(map[string]string)
	store.info["Type"] = "sqlserver"
	store.info["Version"], err = store.getVersion()
	if err != nil {
		log.Error(err.Error())
	}
	store.info["Database"] = database

	store.database.SetConnMaxLifetime(300 * time.Second)
	store.database.SetMaxIdleConns(50)
	store.database.SetMaxOpenConns(50)

	log.Debugf("initialized new mssql service %+v", store)

	return store, err
}

func (store *MSSql) ID() string {
	return "mssql"
}

func (store *MSSql) Database() (db fauth.Database, err error) {
	return store, nil
}

func (store *MSSql) Close() error {
	return store.database.Close()
}

// Health checks to see if the DB is available.
func (store *MSSql) Health() error {
	return store.database.Ping()
}

// Info returns information about the Service.
func (store *MSSql) Info() (info map[string]string) {
	return store.info
}

func (store *MSSql) Load() (acs *fauth.AccessControls, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.database.QueryContext(store.context, "[authz].[GetAccessControlSystem]")

	if err != nil {
		return acs, dbError(err)
	}
	defer rows.Close()

	var acsJSON string
	for rows.Next() {
		err = rows.Scan(&acsJSON)
	}
	if err != nil {
		log.Error(err.Error())
		return acs, NewDBError(err.Error())
	}

	acs = &fauth.AccessControls{}
	err = json.Unmarshal([]byte(acsJSON), acs)
	if err != nil {
		log.Error(err.Error())
		return acs, NewDBError(err.Error())
	}

	return acs, nil
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
