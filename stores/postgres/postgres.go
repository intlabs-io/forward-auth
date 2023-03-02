package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"bitbucket.org/_metalogic_/config"
	. "bitbucket.org/_metalogic_/glib/sql" // dot import fo avoid package prefix in reference (shutup lint)
	"bitbucket.org/_metalogic_/log"
	_ "github.com/lib/pq"
)

// Service implements the storage service interface against PostgreSQL
type Service struct {
	DB      *sql.DB
	context context.Context
	info    map[string]string
}

// New creates a new storage service and sets the database
func New() (svc *Service, err error) {

	server := config.IfGetenv("DB_HOST", "postgres.postgres.svc.cluster.local")
	port := config.IfGetenv("DB_PORT", "5432")
	sslmode := config.IfGetenv("SSL_MODE", "disable")

	name := config.MustGetConfig("DB_NAME")
	user := config.MustGetConfig("DB_USER")
	password := config.MustGetConfig("DB_PASSWORD")

	svc = &Service{context: context.Background()}
	values := url.Values{}
	values.Set("database", name)
	values.Set("sslmode", sslmode)
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     fmt.Sprintf("%s:%s", server, port),
		RawQuery: values.Encode(),
	}

	log.Debugf("PostgreSQL connection string: %s", u.Redacted())

	svc.DB, err = sql.Open("postgres", u.String())
	if err != nil {
		return svc, err
	}

	svc.info = make(map[string]string)
	svc.info["Type"] = "postgres"
	svc.info["Version"], err = Version(svc.DB, "postgres")
	if err != nil {
		log.Error(err.Error())
	}
	svc.info["Database"] = name
	svc.DB.SetConnMaxLifetime(0)
	svc.DB.SetMaxIdleConns(50)
	svc.DB.SetMaxOpenConns(50)
	return svc, err
}

/*******************************
 implement the Store interface
*******************************/

// ID returns the store ID
func (store *Service) ID() string {
	return "postgres"
}

// Close closes the DB connection
func (svc *Service) Close() error {
	return svc.DB.Close()
}

// Health checks to see if the DB is available.
func (svc *Service) Health() error {
	return svc.DB.Ping()
}

// Info returns information about the Service.
func (svc *Service) Info() (info map[string]string) {
	// update with latest database properties
	svc.info["dbstats"] = DBStats(svc.DB)
	return svc.info
}

// Stats returns Service  statistics
func (store *Service) Stats() (js string) {
	// TODO
	return js
}
