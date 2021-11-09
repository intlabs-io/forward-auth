package mssql

import (
	fauth "bitbucket.org/_metalogic_/forward-auth"
)

func (svc Store) Listen(update func(*fauth.AccessControls) error) {
	// TODO
}
