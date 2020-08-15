package fauth

import (
	"bitbucket.org/_metalogic_/ident"
	"bitbucket.org/_metalogic_/pat"
)

// Service ...
type Service interface {
	Authorize(host, method, path string, credentials *ident.Credentials) (status int, message string, err error)
	Block(user string)
	Blocked() []string
	Close()
	Health() error
	Info() string
	Muxer(host string) (hostMux *pat.HostMux, err error)
	Override(host string) string
	HostChecks() (hostChecksJSON string, err error)
	RunMode() string
	SetRunMode(string)
	Stats() string
	Unblock(user string)
}

// type Checks interface {

// }
