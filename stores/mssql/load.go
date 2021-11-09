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

	loader = &Loader{
		context: context.TODO(),
	}

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
		groupGUID, err := loader.createHostGroup(txn, sessionGUID, group)
		if err != nil {
			return n, err
		}
		n = i
		log.Debugf("processing check hosts: %v", group.Hosts)
		for _, host := range group.Hosts {
			hostGUID, err := loader.createHost(txn, sessionGUID, groupGUID, host)
			if err != nil {
				txn.Rollback()
				return n, err
			}
			log.Debugf("created host %s", hostGUID)
		}
		for _, check := range group.Checks {
			checkGUID, err := loader.createCheck(txn, sessionGUID, groupGUID, check)
			if err != nil {
				txn.Rollback()
				return n, err
			}
			log.Debugf("created check %s", checkGUID)
			for _, path := range check.Paths {
				pathGUID, err := loader.createPath(txn, sessionGUID, checkGUID, path)
				if err != nil {
					txn.Rollback()
					return n, err
				}
				log.Debugf("created path %s", pathGUID)
			}
		}
	}

	txn.Commit()
	return n, nil
}

// createHostGroup creates a new host group
func (loader *Loader) createHostGroup(txn *sql.Tx, sessionGUID string, group fauth.HostGroup) (groupID string, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: group name %s", sessionGUID, group.Name)

	rows, err = txn.QueryContext(loader.context, "[authz].[CreateHostGroup]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("Name", group.Name),
		sql.Named("Description", IfNullString(group.Description)),
		sql.Named("Default", group.Default))

	if err != nil {
		return groupID, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&groupID)
	}

	if err != nil {
		log.Errorf("%s", err)
		return groupID, err
	}

	return groupID, err
}

// createHost creates a new check host
func (loader *Loader) createHost(txn *sql.Tx, sessionGUID, groupGUID, hostname string) (hostGUID string, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: hostname %s", sessionGUID, hostname)

	rows, err = txn.QueryContext(loader.context, "[authz].[CreateHost]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
		sql.Named("Hostname", hostname))

	if err != nil {
		return hostGUID, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&hostGUID)
	}

	if err != nil {
		log.Errorf("%s", err)
		return hostGUID, err
	}

	return hostGUID, err
}

// createCheck ...
func (loader *Loader) createCheck(txn *sql.Tx, sessionGUID, groupGUID string, check fauth.Check) (checkGUID string, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: create check %s, access: %s", sessionGUID, check.Name, check.Base)

	rows, err = txn.QueryContext(loader.context, "[authz].[CreateCheck]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
		sql.Named("Name", check.Name),
		sql.Named("Description", IfNullString(check.Description)),
		sql.Named("Version", IfNullInt(check.Version, 0)),
		sql.Named("Base", check.Base))

	if err != nil {
		return checkGUID, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&checkGUID)
	}

	if err != nil {
		log.Errorf("%s", err)
		return checkGUID, err
	}

	return checkGUID, err
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

func (loader *Loader) createPath(txn *sql.Tx, sessionGUID, checkGUID string, path fauth.Path) (pathGUID string, err error) {
	var (
		rows *sql.Rows
	)

	rules, err := json.Marshal(path.Rules)
	if err != nil {
		return pathGUID, err
	}

	log.Debugf("[Session GUID: %s]: create check %s, path: %s, rules %s", sessionGUID, checkGUID, path.Path, string(rules))

	rows, err = txn.QueryContext(loader.context, "[authz].[CreatePath]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("CheckGUID", checkGUID),
		sql.Named("Path", path.Path),
		sql.Named("Rules", string(rules)))

	if err != nil {
		return pathGUID, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&pathGUID)
	}

	if err != nil {
		log.Errorf("%s", err)
		return pathGUID, err
	}

	return pathGUID, err
}

func (loader *Loader) validateRuleS(txn *sql.Tx, rules string) (err error) {

	log.Debug("TODO: validate path rules")

	return nil
}
