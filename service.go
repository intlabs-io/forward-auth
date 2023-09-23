package fauth

import (
	authz "bitbucket.org/_metalogic_/authorize"
)

// Common defines the common service interface
type Common interface {
	Health() error
	Info() map[string]string
	Stats() string
}

// Store defines the storage interface
type Store interface {
	Common
	ID() string
	Close() error
	Database() (Database, error)
	Listen(func(*authz.AccessSystem) error)
	Load() (*authz.AccessSystem, error)
}

type Database interface {
	Blocks() (map[string]bool, error)
	Tokens(root string) (map[string]string, error)

	HostGroups() (groupsJSON string, err error)
	CreateHostGroup(sessionGUID string, group authz.GroupChecks) (groupJSON string, err error)
	HostGroup(groupGUID string) (groupJSON string, err error)
	UpdateHostGroup(sessionGUID, groupGUID string, group authz.GroupChecks) (groupJSON string, err error)
	DeleteHostGroup(groupGUID string) (msgJSON string, err error)

	Hosts(groupGUID string) (hostsJSON string, err error)
	CreateHost(sessionGUID, groupGUID, hostname string) (hostJSON string, err error)
	Host(groupGUID, hostGUID string) (hostJSON string, err error)
	UpdateHost(sessionGUID, groupGUID, hostGUID, hostname string) (hostJSON string, err error)
	DeleteHost(groupGUID, hostGUID string) (msgJSON string, err error)

	Checks(groupGUID string) (checksJSON string, err error)
	CreateCheck(sessionGUID, groupGUID string, check authz.Check) (checkJSON string, err error)
	Check(groupGUID, checkGUID string) (checkJSON string, err error)
	UpdateCheck(sessionGUID, groupGUID, checkGUID string, check authz.Check) (checkJSON string, err error)
	DeleteCheck(groupGUID, checkGUID string) (msgJSON string, err error)

	Paths(groupGUID, checkGUID string) (pathsJSON string, err error)
	CreatePath(sessionGUID, groupGUID, checkGUID string, path authz.Path) (pathJSON string, err error)
	Path(groupGUID, checkGUID, pathGUID string) (pathJSON string, err error)
	UpdatePath(sessionGUID, goupdGUID, checkGUID, pathGUID string, path authz.Path) (pathJSON string, err error)
	DeletePath(groupGUID, checkGUID, pathGUID string) (msgJSON string, err error)
}
