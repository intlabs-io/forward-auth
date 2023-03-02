package sql

import (
	"fmt"

	"bitbucket.org/_metalogic_/glib/http"
	mssql "github.com/denisenkom/go-mssqldb"
	pq "github.com/lib/pq"
)

func DBError(err error) error {
	if err == nil {
		return nil
	}
	if mssqlErr, ok := err.(mssql.Error); ok {
		// SQLServer API errors use HTTP status code + application base code 50000
		code := mssqlErr.SQLErrorNumber()
		code = code - 50000

		switch code {
		case 400:
			return http.NewBadRequestError(mssqlErr.SQLErrorMessage())
		case 404:
			return http.NewNotFoundError(mssqlErr.SQLErrorMessage())
		case 500:
			return http.NewServerError(fmt.Sprintf("%s: %s", mssqlErr.SQLErrorServerName(), mssqlErr.SQLErrorMessage()))
		default:
			return http.NewBadRequestError(mssqlErr.SQLErrorMessage())
		}
	} else if postgresErr, ok := err.(*pq.Error); ok {
		// PostgreSQL API errors use string "HS" followed by HTTP status code
		code := postgresErr.Code.Name()

		switch code {
		case "HS400":
			return http.NewBadRequestError(postgresErr.Message)
		case "HS404":
			return http.NewNotFoundError(postgresErr.Message)
		case "HS500":
			return http.NewServerError(postgresErr.Message)
		default:
			return http.NewBadRequestError(postgresErr.Message)
		}
	}
	return http.NewServerError(err.Error())
}
