package mssql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	_ "github.com/denisenkom/go-mssqldb"
	mssql "github.com/denisenkom/go-mssqldb"
)

// Service implements the forward-auth service interface against Microsoft SQLServer
type Service struct {
	database *sql.DB
	context  context.Context
	prefix   string
	tokens   map[string]string
	blocks   map[string]bool
	runMode  string
	lock     sync.RWMutex
	version  string
}

// New creates a new Service and sets the database
func New(prefix string, tokens map[string]string, blocks map[string]bool, database, server string, port int, user, password, runMode string) (svc *Service, err error) {
	svc = &Service{
		prefix:  prefix,
		context: context.TODO(),
		blocks:  blocks,
		tokens:  tokens,
		runMode: runMode}
	values := url.Values{}
	values.Set("database", database)
	values.Set("app", "EPBC applications-api")
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(user, password),
		Host:   fmt.Sprintf("%s:%d", server, port),
		// Path:  instance, // if connecting to an instance instead of a port
		RawQuery: values.Encode(),
	}
	log.Debugf("sqlserver connection string: %s", u.String())
	svc.database, err = sql.Open("sqlserver", u.String())
	if err != nil {
		return svc, err
	}
	if err = svc.setVersion(); err != nil {
		log.Error(err.Error())
	}
	svc.database.SetConnMaxLifetime(300 * time.Second)
	svc.database.SetMaxIdleConns(50)
	svc.database.SetMaxOpenConns(50)

	return svc, err
}

// Close closes the DB connection
func (svc *Service) Close() {
	svc.database.Close()
}

// Health checks to see if the DB is available.
func (svc *Service) Health() error {
	return svc.database.Ping()
}

// Info return information about the Service.
func (svc *Service) Info() string {
	info := &info{}
	info.Hostname = os.Getenv("HOSTNAME")
	info.Database = "TODO replace with value of dbname"
	info.MSSql = svc.Version()
	info.LogLevel = log.GetLevel().String()
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return fmt.Sprintf("failed to marshal info from %v", info)
	}
	return string(infoJSON)
}

// Stats returns Service  statistics
func (svc *Service) Stats() string {
	dbstats := svc.database.Stats()
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

// Version returns the database version
func (svc *Service) Version() string {
	return svc.version
}

func (svc *Service) setVersion() (err error) {
	_, err = svc.database.QueryContext(svc.context, "[dbo].[Version]", sql.Named("Version", sql.Out{Dest: &(svc.version)}))
	if err != nil {
		log.Errorf("%s", err)
	}
	return err
}

// ifnullString invalidates a sql.NullString if empty, validates if not empty
func ifnullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// ifnullInt validates a sql.NullInt64 if i is equal to nullValue, invalidates if it does not
func ifnullInt(i, nullValue int) sql.NullInt64 {
	if i == nullValue {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(i), Valid: true}
}

func ifnullIntString(s string) sql.NullInt64 {
	i, err := strconv.Atoi(s)
	return sql.NullInt64{Int64: int64(i), Valid: err == nil}
}

//ToNullString invalidates a sql.NullString if empty, validates if not empty
func ToNullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func ifnullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

//ToNullTime invalidates a sql.NullTime if empty, validates if not empty
func ToNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

// ifnullBool invalidates a sql.NullBool if incoming bool is equal to nullValue
func ifnullBool(t, nullValue bool) sql.NullBool {
	if t == nullValue {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: t, Valid: true}
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
		return fauth.NewBadRequestError(dberr.SQLErrorMessage())
	case 404:
		return fauth.NewNotFoundError(dberr.SQLErrorMessage())
	case 500:
		return fauth.NewServerError(fmt.Sprintf("%s: %s", dberr.SQLErrorServerName(), dberr.SQLErrorMessage()))
	default:
		return fauth.NewBadRequestError(dberr.SQLErrorMessage())
	}
}
