package postgres

import (
	fauth "bitbucket.org/_metalogic_/forward-auth"
)

func (store Service) Database() (database fauth.Database, err error) {
	return database, err
}

func (store Service) Listen(func(*fauth.AccessSystem) error) {
}

func (store Service) Load() (as *fauth.AccessSystem, err error) {
	return as, err
}
