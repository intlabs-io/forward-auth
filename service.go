package fauth

import (
	"bitbucket.org/_metalogic_/ident"
	"bitbucket.org/_metalogic_/pat"
)

// Service ...
type Service interface {
	AllowHost(host string) bool
	DenyHost(host string) bool
	Authorize(host, method, path string, credentials *ident.Credentials) (status int, message string, err error)
	Block(user string)
	Blocked() []string
	Checks(host string) (hostMux *pat.HostMux, err error)
	Close()
	Health() error
	Info() string
	Rules() (rulesJSON string, err error)
	RunMode() string
	SetRunMode(string)
	Stats() string
	Unblock(user string)
}
