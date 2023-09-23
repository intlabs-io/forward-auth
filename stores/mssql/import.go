package mssql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"time"

	authz "bitbucket.org/_metalogic_/authorize"
	"bitbucket.org/_metalogic_/config"
	. "bitbucket.org/_metalogic_/glib/sql" // dot import fo avoid package prefix in reference (shutup lint)
	"bitbucket.org/_metalogic_/log"
	_ "github.com/denisenkom/go-mssqldb"
)

// Loader implements a data loader for the forward-auth database schema
type Loader struct {
	DB      *sql.DB
	context context.Context
}

// NewLoader creates a new database loader
func NewLoader() (loader *Loader, err error) {

	name := config.MustGetConfig("DB_NAME")
	user := config.MustGetConfig("API_DB_USER")
	password := config.MustGetConfig("API_DB_PASSWORD")

	server := config.IfGetenv("DB_HOST", "mssql.mssql.svc.cluster.local")
	port := config.IfGetInt("DB_PORT", 1433)

	loader = &Loader{context: context.Background()}
	// configure MSSql Server
	values := url.Values{}
	values.Set("database", name)
	values.Set("app", "forward-auth loader")
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(user, password),
		Host:   fmt.Sprintf("%s:%d", server, port),
		// Path:  instance, // if connecting to an instance instead of a port
		RawQuery: values.Encode(),
	}

	log.Debugf("sqlserver connection string: %s", u.Redacted())

	loader.DB, err = sql.Open("sqlserver", u.String())
	if err != nil {
		return loader, err
	}
	loader.DB.SetConnMaxLifetime(300 * time.Second)
	loader.DB.SetMaxIdleConns(50)
	loader.DB.SetMaxOpenConns(50)

	if err = loader.DB.Ping(); err != nil {
		return loader, err
	}

	return loader, nil
}

// Import imports an access control file to the database
func (loader *Loader) Import(file string) (n int, err error) {

	var acs authz.AccessSystem

	// load access.json from file
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return n, err
	}

	err = json.Unmarshal(data, &acs)
	if err != nil {
		return n, err
	}

	log.Debugf("loaded access system from file %s: %+v", file, acs)

	sessionGUID := "ROOT"

	txn, err := loader.DB.BeginTx(context.TODO(), nil)
	if err != nil {
		log.Error(err)
		return n, err
	}

	for i, group := range acs.Authorization.GroupChecks {
		groupGUID, groupJSON, err := createHostGroup(txn, sessionGUID, group)
		if err != nil {
			return n, err
		}
		log.Debugf("importing group %s: %s", groupGUID, groupJSON)
		n = i + 1
		log.Debugf("processing check groups: %v", group.Groups)
		for _, group := range group.Groups {
			groupGUID, groupJSON, err := createGroup(txn, sessionGUID, groupGUID, group)
			if err != nil {
				txn.Rollback()
				return n, err
			}
			log.Debugf("created group %s: %s", groupGUID, groupJSON)
		}
		for _, check := range group.Checks {
			checkGUID, checkJSON, err := createCheck(txn, sessionGUID, groupGUID, check)
			if err != nil {
				txn.Rollback()
				return n, err
			}
			log.Debugf("created check %s: %s", checkGUID, checkJSON)
			for _, path := range check.Paths {
				pathGUID, pathJSON, err := createPath(txn, sessionGUID, checkGUID, path)
				if err != nil {
					txn.Rollback()
					return n, err
				}
				log.Debugf("created path %s: %s", pathGUID, pathJSON)
			}
		}
	}

	txn.Commit()
	return n, nil
}

func createSystem(txn *sql.Tx, sessionGUID, name, description string) (systemGUID, systemJSON string, err error) {
	var (
		rows *sql.Rows
	)

	ctx := context.TODO()
	rows, err = txn.QueryContext(ctx, "[authz].[CreateSystem]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("Name", name),
		sql.Named("Description", IfNullString(description)),
		sql.Named("GUID", sql.Out{Dest: &systemGUID}))

	if err != nil {
		return systemGUID, systemJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&systemJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return systemGUID, systemJSON, err
	}

	return systemGUID, systemJSON, err
}

func createHostGroup(txn *sql.Tx, sessionGUID string, group authz.GroupChecks) (groupGUID, groupJSON string, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: group name %s", sessionGUID, group.Name)

	ctx := context.TODO()
	rows, err = txn.QueryContext(ctx, "[authz].[CreateHostGroup]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("Name", group.Name),
		sql.Named("Description", IfNullString(group.Description)),
		sql.Named("Default", group.Default),
		sql.Named("GUID", sql.Out{Dest: &groupGUID}))

	if err != nil {
		return groupGUID, groupJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&groupJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return groupGUID, groupJSON, err
	}

	return groupGUID, groupJSON, err
}

// createGroup creates a new check group
func createGroup(txn *sql.Tx, sessionGUID, groupGUID, groupname string) (guid, groupJSON string, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: groupname %s", sessionGUID, groupname)

	ctx := context.TODO()
	rows, err = txn.QueryContext(ctx, "[authz].[CreateHost]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
		sql.Named("Hostname", groupname),
		sql.Named("GUID", sql.Out{Dest: &groupGUID}))

	if err != nil {
		return guid, groupJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&groupJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return guid, groupJSON, err
	}

	return guid, groupJSON, err
}

// createCheck ...
func createCheck(txn *sql.Tx, sessionGUID, groupGUID string, check authz.Check) (checkGUID, checkJSON string, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: create check %s, access: %s", sessionGUID, check.Name, check.Base)

	ctx := context.TODO()
	rows, err = txn.QueryContext(ctx, "[authz].[CreateCheck]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
		sql.Named("Name", check.Name),
		sql.Named("Description", IfNullString(check.Description)),
		sql.Named("Version", IfNullInt(check.Version, 0)),
		sql.Named("Base", check.Base),
		sql.Named("GUID", sql.Out{Dest: &checkGUID}))

	if err != nil {
		return checkGUID, checkJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&checkJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return checkGUID, checkJSON, err
	}

	return checkGUID, checkJSON, err
}

func createPath(txn *sql.Tx, sessionGUID, checkGUID string, path authz.Path) (pathGUID, pathJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rules, err := json.Marshal(path.Rules)
	if err != nil {
		return pathGUID, pathJSON, err
	}

	log.Debugf("[Session GUID: %s]: create check %s, path: %s, rules %s", sessionGUID, checkGUID, path.Path, string(rules))

	ctx := context.TODO()
	rows, err = txn.QueryContext(ctx, "[authz].[CreatePath]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("CheckGUID", checkGUID),
		sql.Named("Path", path.Path),
		sql.Named("Rules", string(rules)),
		sql.Named("GUID", sql.Out{Dest: &pathGUID}))

	if err != nil {
		return pathGUID, pathJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&pathJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return pathGUID, pathJSON, err
	}

	return pathGUID, pathJSON, err
}

// getCheck ...
func (loader *Loader) getCheck(txn *sql.Tx, checkGUID string) (checkJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = txn.QueryContext(loader.context, "[authz].[GetCheck]",
		sql.Named("CheckGUID", checkGUID))

	if err != nil {
		return checkJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&checkJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return checkJSON, err
	}

	return checkJSON, err
}

func (loader *Loader) validateRuleS(txn *sql.Tx, rules string) (err error) {

	log.Debug("TODO: validate path rules")

	return nil
}
