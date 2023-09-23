package mssql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	authz "bitbucket.org/_metalogic_/authorize"
	"bitbucket.org/_metalogic_/config"
	. "bitbucket.org/_metalogic_/glib/http" // dot import fo avoid package prefix in reference (shutup lint)
	. "bitbucket.org/_metalogic_/glib/sql"
	"bitbucket.org/_metalogic_/log"
)

// MSSql implements the forward-auth store interface against Microsoft SQLServer
type MSSql struct {
	DB      *sql.DB
	context context.Context
	info    map[string]string
}

// New creates a new SQL Server storage service and sets the database
func New() (store *MSSql, err error) {
	name := config.MustGetConfig("DB_NAME")
	user := config.MustGetConfig("DB_USER")
	password := config.MustGetConfig("DB_PASSWORD")

	server := config.IfGetenv("DB_HOST", "mssql.mssql.svc.cluster.local")
	port := config.IfGetInt("DB_PORT", 1433)

	store = &MSSql{context: context.Background()}
	// configure MSSql Server
	values := url.Values{}
	values.Set("database", name)
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
	info["Database"] = name
	info["Type"] = "sqlserver"
	store.info["Version"], err = Version(store.DB, "postgres")
	if err != nil {
		log.Error(err.Error())
	}
	store = &MSSql{
		DB:      db,
		context: context.TODO(),
		info:    info,
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
	return store.DB.Close()
}

// Load loads an access control system from the database
func (store *MSSql) Load() (acs *authz.AccessSystem, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.DB.QueryContext(store.context, "[authz].[GetAccessControlSystem]")

	if err != nil {
		return acs, DBError(err)
	}
	defer rows.Close()

	var authorizationJSON string
	for rows.Next() {
		err = rows.Scan(&authorizationJSON)
	}
	if err != nil {
		log.Error(err.Error())
		return acs, NewDBError(err.Error())
	}

	authorization := &authz.Authorization{}
	err = json.Unmarshal([]byte(authorizationJSON), authorization)
	if err != nil {
		log.Error(err.Error())
		return acs, NewDBError(err.Error())
	}

	acs = &authz.AccessSystem{
		Authorization: authorization,
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
	// TODO
	// load applications from file
	// data, err := ioutil.ReadFile(store.applications)
	// if err != nil {
	// 	return tokens, err
	// }

	// var applications []authz.Application

	// err = json.Unmarshal(data, applications)
	// if err != nil {
	// 	return tokens, err
	// }

	// log.Debugf("loaded applications from '%s': %+v", store.applications, applications)

	// tokens = make(map[string]string)

	// // load application bearer token mappings from token value to token name
	// for _, application := range applications {
	// 	if application.Bearer != nil && application.Bearer.Source == "docker" {
	// 		tokens[config.MustGetConfig(application.Bearer.Name)] = application.Bearer.Name
	// 	}
	// }
	return tokens, nil
}

/*******************************
 implement the Common interface
********************************/

// Health checks to see if the DB is available.
func (store *MSSql) Health() error {
	return store.DB.Ping()
}

// Info returns information about the Service.
func (store *MSSql) Info() (info map[string]string) {
	return store.info
}

// Stats returns Service  statistics
func (store *MSSql) Stats() string {
	dbstats := store.DB.Stats()
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

func (store *MSSql) Listen(func(*authz.AccessSystem) error) {
}
