package mssql

import (
	fauth "bitbucket.org/_metalogic_/forward-auth"
)

func (svc MSSql) Listen(update func(*fauth.AccessControls) error) {
	// TODO
}
