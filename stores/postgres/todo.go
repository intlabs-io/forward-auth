package postgres

import (
	authz "bitbucket.org/_metalogic_/authorize"
	fauth "bitbucket.org/_metalogic_/forward-auth"
)

func (store Service) Database() (database fauth.Database, err error) {
	return database, err
}

func (store Service) Listen(func(*authz.AccessSystem) error) {
}

func (store Service) Load() (as *authz.AccessSystem, err error) {
	return as, err
}
