package mssql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"time"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/sql" // dot import fo avoid package prefix in reference (shutup lint)
	"bitbucket.org/_metalogic_/log"
	_ "github.com/denisenkom/go-mssqldb"
)

// Loader implements a data loader for the forward-auth database schema
type Loader struct {
	database *sql.DB
	context  context.Context
}

// NewLoader creates a new database loader
func NewLoader(database, server string, port int, user, password string) (loader *Loader, err error) {

	loader = &Loader{}

	// configure MSSql Server
	values := url.Values{}
	values.Set("database", database)
	values.Set("app", "forward-auth loader")
	u := &url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(user, password),
		Host:     fmt.Sprintf("%s:%d", server, port),
		RawQuery: values.Encode(),
	}
	log.Debugf("sqlserver connection string: %s", u.Redacted())

	loader.database, err = sql.Open("sqlserver", u.String())
	if err != nil {
		return loader, err
	}
	loader.database.SetConnMaxLifetime(300 * time.Second)
	loader.database.SetMaxIdleConns(50)
	loader.database.SetMaxOpenConns(50)

	if err = loader.database.Ping(); err != nil {
		return loader, err
	}

	return loader, nil
}

// Import imports an access control file to the database
func (loader *Loader) Import(file string) (n int, err error) {

	var ac fauth.AccessControls

	// load checks from file
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return n, err
	}

	err = json.Unmarshal(data, &ac)
	if err != nil {
		return n, err
	}

	log.Debugf("loaded checks: %+v", ac)

	sessionGUID := "ROOT"

	txn, err := loader.database.BeginTx(context.TODO(), nil)
	if err != nil {
		log.Error(err)
		return n, err
	}

	for i, group := range ac.HostGroups {
		groupGUID, groupJSON, err := createHostGroup(txn, sessionGUID, group)
		if err != nil {
			return n, err
		}
		log.Debugf("importing host group %s: %s", groupGUID, groupJSON)
		n = i + 1
		log.Debugf("processing check hosts: %v", group.Hosts)
		for _, host := range group.Hosts {
			hostGUID, hostJSON, err := createHost(txn, sessionGUID, groupGUID, host)
			if err != nil {
				txn.Rollback()
				return n, err
			}
			log.Debugf("created host %s: %s", hostGUID, hostJSON)
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

func createHostGroup(txn *sql.Tx, sessionGUID string, group fauth.HostGroup) (groupGUID, groupJSON string, err error) {
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

// createHost creates a new check host
func createHost(txn *sql.Tx, sessionGUID, groupGUID, hostname string) (hostGUID, hostJSON string, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: hostname %s", sessionGUID, hostname)

	ctx := context.TODO()
	rows, err = txn.QueryContext(ctx, "[authz].[CreateHost]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
		sql.Named("Hostname", hostname),
		sql.Named("GUID", sql.Out{Dest: &hostGUID}))

	if err != nil {
		return hostGUID, hostJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&hostJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return hostGUID, hostJSON, err
	}

	return hostGUID, hostJSON, err
}

// createCheck ...
func createCheck(txn *sql.Tx, sessionGUID, groupGUID string, check fauth.Check) (checkGUID, checkJSON string, err error) {
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

func createPath(txn *sql.Tx, sessionGUID, checkGUID string, path fauth.Path) (pathGUID, pathJSON string, err error) {
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
