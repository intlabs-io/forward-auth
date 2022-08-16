package mssql

import (
	"context"
	"database/sql"
	"encoding/json"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/sql"
	"bitbucket.org/_metalogic_/log"
)

/*******************************
 implement the Database interface
********************************/

// Database returns a database implementation
func (store *MSSql) Database() (db fauth.Database, err error) {
	return store, nil
}

func (store *MSSql) HostGroups() (groupsJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.DB.QueryContext(store.context, "[authz].[GetHostGroups]")

	if err != nil {
		return groupsJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&groupsJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return groupsJSON, err
	}

	return groupsJSON, err
}

func (store *MSSql) CreateHostGroup(sessionGUID string, group fauth.HostGroup) (groupJSON string, err error) {
	txn, err := store.DB.BeginTx(context.TODO(), nil)
	if err != nil {
		log.Error(err)
		return groupJSON, err
	}

	groupGUID, groupJSON, err := createHostGroup(txn, sessionGUID, group)
	if err != nil {
		return groupJSON, err
	}
	log.Debugf("processing check hosts: %v", group.Hosts)
	for _, host := range group.Hosts {
		hostGUID, hostJSON, err := createHost(txn, sessionGUID, groupGUID, host)
		if err != nil {
			txn.Rollback()
			return groupJSON, err
		}
		log.Debugf("created host %s: %s", hostGUID, hostJSON)
	}
	txn.Commit()

	return store.HostGroup(groupGUID)
}

func (store *MSSql) HostGroup(groupGUID string) (groupJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.DB.QueryContext(store.context, "[authz].[GetHostGroup]",
		sql.Named("GroupGUID", groupGUID))

	if err != nil {
		return groupJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&groupJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return groupJSON, err
	}

	return groupJSON, err

}
func (store *MSSql) UpdateHostGroup(sessionGUID, groupGUID string, group fauth.HostGroup) (groupJSON string, err error) {
	var (
		rows *sql.Rows
	)

	log.Debugf("[Session GUID: %s]: update host group %s", sessionGUID, group.Name)

	rows, err = store.DB.QueryContext(store.context, "[authz].[UpdateHostGroup]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("Name", group.Name),
		sql.Named("Description", IfNullString(group.Description)),
		sql.Named("Default", group.Default))

	if err != nil {
		return groupJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&groupJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return groupJSON, err
	}

	return groupJSON, err
}
func (store *MSSql) DeleteHostGroup(groupGUID string) (msgJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.DB.QueryContext(store.context, "[authz].[DeleteHostGroup]",
		sql.Named("GroupGUID", groupGUID))

	if err != nil {
		return msgJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&msgJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return msgJSON, err
	}

	return msgJSON, err
}

func (store *MSSql) Hosts(groupGUID string) (hostsJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.DB.QueryContext(store.context, "[authz].[GetHosts]",
		sql.Named("GroupGUID", groupGUID))

	if err != nil {
		return hostsJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&hostsJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return hostsJSON, err
	}

	return hostsJSON, err
}

func (store *MSSql) CreateHost(sessionGUID, groupGUID string, hostname string) (hostJSON string, err error) {
	var (
		hostGUID string
		rows     *sql.Rows
	)

	log.Debugf("[Session GUID: %s]: update host group %s", sessionGUID, hostname)

	rows, err = store.DB.QueryContext(store.context, "[authz].[CreateHost]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
		sql.Named("Hostname", hostname),
		sql.Named("GUID", sql.Out{Dest: &hostGUID}))

	if err != nil {
		return hostJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&hostJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return hostJSON, err
	}

	return store.Host(groupGUID, hostGUID)
}

func (store *MSSql) Host(groupGUID, hostGUID string) (hostJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.DB.QueryContext(store.context, "[authz].[GetHost]",
		sql.Named("GroupGUID", groupGUID),
		sql.Named("HostGUID", hostGUID))

	if err != nil {
		return hostJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&hostJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return hostJSON, err
	}

	return hostJSON, err
}

func (store *MSSql) UpdateHost(sessionGUID, groupGUID, hostGUID string, hostname string) (hostJSON string, err error) {
	var (
		rows *sql.Rows
	)

	log.Debugf("[Session GUID: %s]: update host group %s", sessionGUID, hostname)

	rows, err = store.DB.QueryContext(store.context, "[authz].[UpdateHost]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
		sql.Named("HostGUID", hostGUID),
		sql.Named("Hostname", hostname))

	if err != nil {
		return hostJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&hostJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return hostJSON, err
	}

	return store.Host(groupGUID, hostGUID)
}

func (store *MSSql) DeleteHost(groupGUID, hostGUID string) (msgJSON string, err error) {
	var (
		rows *sql.Rows
	)

	log.Debugf("delete host %s", hostGUID)

	rows, err = store.DB.QueryContext(store.context, "[authz].[DeleteHost]",
		sql.Named("GroupGUID", groupGUID),
		sql.Named("HostGUID", hostGUID))

	if err != nil {
		return msgJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&msgJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return msgJSON, err
	}

	return msgJSON, err
}

func (store *MSSql) Checks(groupGUID string) (checksJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.DB.QueryContext(store.context, "[authz].[GetChecks]",
		sql.Named("GroupGUID", groupGUID))

	if err != nil {
		return checksJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&checksJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return checksJSON, err
	}

	return checksJSON, err
}

func (store *MSSql) CreateCheck(sessionGUID, groupGUID string, check fauth.Check) (checkJSON string, err error) {
	var (
		checkGUID string
		rows      *sql.Rows
	)

	log.Debugf("[Session GUID: %s]: create host check for group %s", sessionGUID, groupGUID)

	rows, err = store.DB.QueryContext(store.context, "[authz].[CreateCheck]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
		sql.Named("Name", check.Name),
		sql.Named("Description", IfNullString(check.Description)),
		sql.Named("Version", IfNullInt(check.Version, 0)),
		sql.Named("Base", check.Base),
		sql.Named("GUID", sql.Out{Dest: &checkGUID}))

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

	return store.Check(groupGUID, checkGUID)
}

func (store *MSSql) Check(groupGUID, checkGUID string) (checkJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.DB.QueryContext(store.context, "[authz].[GetCheck]",
		sql.Named("GroupGUID", groupGUID),
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

func (store *MSSql) UpdateCheck(sessionGUID, groupGUID, checkGUID string, check fauth.Check) (checkJSON string, err error) {
	var (
		rows *sql.Rows
	)

	log.Debugf("[Session GUID: %s]: update check %s for group %s", sessionGUID, checkGUID, groupGUID)

	rows, err = store.DB.QueryContext(store.context, "[authz].[UpdateCheck]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
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

	return store.Check(groupGUID, checkGUID)
}

func (store *MSSql) DeleteCheck(groupGUID, checkGUID string) (msgJSON string, err error) {
	var (
		rows *sql.Rows
	)

	log.Debugf("delete check %s for group %s", checkGUID, groupGUID)

	rows, err = store.DB.QueryContext(store.context, "[authz].[DeleteCheck]",
		sql.Named("GroupGUID", groupGUID),
		sql.Named("HostGUID", checkGUID))

	if err != nil {
		return msgJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&msgJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return msgJSON, err
	}

	return msgJSON, err
}

func (store *MSSql) Paths(groupGUID, checkGUID string) (pathsJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.DB.QueryContext(store.context, "[authz].[GetPaths]",
		sql.Named("GroupGUID", groupGUID),
		sql.Named("CheckGUID", checkGUID))

	if err != nil {
		return pathsJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&pathsJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return pathsJSON, err
	}

	return pathsJSON, err
}

func (store *MSSql) CreatePath(sessionGUID, groupGUID, checkGUID string, path fauth.Path) (pathJSON string, err error) {
	var (
		pathGUID string
		rows     *sql.Rows
	)

	log.Debugf("[Session GUID: %s]: create path for host check %s, host group %s", sessionGUID, checkGUID, groupGUID)

	rules, err := json.Marshal(path.Rules)
	if err != nil {
		return pathJSON, err
	}

	rows, err = store.DB.QueryContext(store.context, "[authz].[CreatePath]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
		sql.Named("CheckGUID", checkGUID),
		sql.Named("Path", path.Path),
		sql.Named("Rules", string(rules)),
		sql.Named("GUID", sql.Out{Dest: &pathGUID}))

	if err != nil {
		return pathJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&pathJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return pathJSON, err
	}

	return store.Path(groupGUID, checkGUID, pathGUID)
}

func (store *MSSql) Path(groupGUID, checkGUID, pathGUID string) (pathJSON string, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = store.DB.QueryContext(store.context, "[authz].[GetPath]",
		sql.Named("GroupGUID", groupGUID),
		sql.Named("CheckGUID", checkGUID),
		sql.Named("PathGUID", pathGUID))

	if err != nil {
		return pathGUID, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&pathJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return pathGUID, err
	}

	return pathJSON, err
}

func (store *MSSql) UpdatePath(sessionGUID, groupGUID, checkGUID, pathGUID string, path fauth.Path) (pathJSON string, err error) {
	var (
		rows *sql.Rows
	)

	log.Debugf("[Session GUID: %s]: update check path %s", sessionGUID, pathGUID)

	rules, err := json.Marshal(path.Rules)
	if err != nil {
		return pathJSON, err
	}

	rows, err = store.DB.QueryContext(store.context, "[authz].[UpdatePath]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("GroupGUID", groupGUID),
		sql.Named("CheckGUID", checkGUID),
		sql.Named("PathGUID", pathGUID),
		sql.Named("Path", path.Path),
		sql.Named("Rules", string(rules)))

	if err != nil {
		return pathJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&pathJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return pathJSON, err
	}

	return store.Path(groupGUID, checkGUID, pathGUID)
}

func (store *MSSql) DeletePath(groupGUID, checkGUID, pathGUID string) (msgJSON string, err error) {
	var (
		rows *sql.Rows
	)

	log.Debugf("delete host %s", pathGUID)

	rows, err = store.DB.QueryContext(store.context, "[authz].[DeletePath]",
		sql.Named("GroupGUID", groupGUID),
		sql.Named("CheckGUID", checkGUID),
		sql.Named("PathGUID", pathGUID))

	if err != nil {
		return msgJSON, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&msgJSON)
	}

	if err != nil {
		log.Errorf("%s", err)
		return msgJSON, err
	}

	return msgJSON, err
}
