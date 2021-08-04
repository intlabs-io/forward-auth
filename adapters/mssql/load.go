package mssql

import (
	"context"
	"database/sql"
	"fmt"
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
	log.Debugf("sqlserver connection string: %s", u.String())
	loader.database, err = sql.Open("sqlserver", u.String())
	if err != nil {
		return loader, err
	}
	loader.database.SetConnMaxLifetime(300 * time.Second)
	loader.database.SetMaxIdleConns(50)
	loader.database.SetMaxOpenConns(50)

	return loader, nil
}

// Load loads AccessControls to the database
func (loader *Loader) Load(ac fauth.AccessControls) (n int, err error) {

	sessionGUID := "ROOT"

	// TODO wrap in transaction
	txn, err := loader.database.BeginTx(context.TODO(), nil)
	if err != nil {
		return n, err
	}
	for i, hostCheck := range ac.HostChecks {
		n = i
		log.Debugf("processing check hosts: %v", hostCheck.Hosts)
		for j, host := range hostCheck.Hosts {
			hostID, err := loader.createHost(sessionGUID, host)
			if err != nil {
				txn.Rollback()
				return n, err
			}
			if len(hostCheck.Checks) == 0 {
				err = loader.createHostCheck(sessionGUID, hostID, hostCheck.Default, 0)
				if err != nil {
					txn.Rollback()
					return n, err
				}
				continue
			}
			for _, check := range hostCheck.Checks {
				var checkID int
				if j == 0 { // only create the check for the first host, remaining hosts reuse it
					checkID, err = loader.createCheck(sessionGUID, check.Name, check.Base)
					if err != nil {
						txn.Rollback()
						return n, err
					}
					for _, path := range check.Paths {
						pathID, err := loader.createPath(sessionGUID, checkID, path.Path)
						if err != nil {
							txn.Rollback()
							return n, err
						}
						for _, method := range []fauth.Method{"GET", "POST", "PUT", "DELETE", "HEAD"} {
							if r, ok := path.Rules[method]; ok {
								err := loader.createRule(sessionGUID, pathID, string(method), r.Description, r.Expression)
								if err != nil {
									txn.Rollback()
									return n, err
								}
							}
						}
					}
				} else {
					checkID, err = loader.getCheck(check.Name, check.Base)
					if err != nil {
						txn.Rollback()
						return n, err
					}
				}
				err = loader.createHostCheck(sessionGUID, hostID, hostCheck.Default, checkID)
				if err != nil {
					txn.Rollback()
					return n, err
				}
			}
		}
	}

	for hostname, access := range ac.Overrides {
		err := loader.createOverride(sessionGUID, hostname, access)
		if err != nil {
			txn.Rollback()
			return n, err
		}
		log.Warningf("host checks are disabled by override for %s", hostname)
	}
	txn.Commit()
	return n, nil
}

// createHost creates a new check host
func (loader *Loader) createHost(sessionGUID, hostname string) (hostID int, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: hostname %s", sessionGUID, hostname)

	rows, err = loader.database.QueryContext(loader.context, "[auth].[CreateHost]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("Hostname", hostname))

	if err != nil {
		return hostID, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&hostID)
	}

	if err != nil {
		log.Errorf("%s", err)
		return hostID, err
	}

	return hostID, err
}

// createCheck ...
func (loader *Loader) createCheck(sessionGUID string, name, base string) (checkID int, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: hostname %s, access: %s", sessionGUID, name, base)

	rows, err = loader.database.QueryContext(loader.context, "[auth].[CreateCheck]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("Name", name),
		sql.Named("Base", base))

	if err != nil {
		return checkID, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&checkID)
	}

	if err != nil {
		log.Errorf("%s", err)
		return checkID, err
	}

	return checkID, err
}

// getCheck ...
func (loader *Loader) getCheck(name, base string) (checkID int, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("get check for name %s, access: %s", name, base)

	rows, err = loader.database.QueryContext(loader.context, "[auth].[GetCheck]",
		sql.Named("Name", name),
		sql.Named("Base", base))

	if err != nil {
		return checkID, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&checkID)
	}

	if err != nil {
		log.Errorf("%s", err)
		return checkID, err
	}

	return checkID, err
}

// createCheck ...
func (loader *Loader) createHostCheck(sessionGUID string, hostID int, defaultAccess string, checkID int) (err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: hostID %d, checkID: %d", sessionGUID, hostID, checkID)

	rows, err = loader.database.QueryContext(loader.context, "[auth].[CreateHostCheck]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("HostID", hostID),
		sql.Named("DefaultAccess", defaultAccess),
		sql.Named("CheckID", IfNullInt(checkID, 0)))

	if err != nil {
		return err
	}

	defer rows.Close()

	return nil
}

func (loader *Loader) createPath(sessionGUID string, checkID int, path string) (pathID int, err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: checkID %d, path: %s", sessionGUID, checkID, path)

	rows, err = loader.database.QueryContext(loader.context, "[auth].[CreatePath]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("CheckID", checkID),
		sql.Named("Path", path))

	if err != nil {
		return pathID, err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&pathID)
	}

	if err != nil {
		log.Errorf("%s", err)
		return pathID, err
	}

	return pathID, err
}

func (loader *Loader) createRule(sessionGUID string, pathID int, method, description, expression string) (err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: method: %s, pathID %d, description: %s, expression: %s", sessionGUID, method, pathID, description, expression)

	rows, err = loader.database.QueryContext(loader.context, "[auth].[CreateRule]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("PathID", pathID),
		sql.Named("Method", method),
		sql.Named("Description", description),
		sql.Named("Expr", expression))

	if err != nil {
		return err
	}

	defer rows.Close()

	return nil
}

func (loader *Loader) createOverride(sessionGUID, hostname string, permission string) (err error) {
	var (
		rows *sql.Rows
	)
	log.Debugf("[Session GUID: %s]: hostname %s, permission: %d", sessionGUID, hostname, permission)

	rows, err = loader.database.QueryContext(loader.context, "[auth].[CreateOverride]",
		sql.Named("SessionGUID", sessionGUID),
		sql.Named("Hostname", hostname),
		sql.Named("Permission", permission))

	if err != nil {
		return err
	}

	defer rows.Close()

	return nil
}
