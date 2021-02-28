package fauth

import (
	"bitbucket.org/_metalogic_/ident"
	"bitbucket.org/_metalogic_/pat"
)

// Common defines the common service interface
type Common interface {
	Health() error
	Info() map[string]string
	Stats() string
}

// Service defines the Curriculum service interface
type Service interface {
	Common
	Authorize(host, method, path string, credentials *ident.Credentials) (status int, message string, err error)
	Block(user string)
	Blocked() []string
	Close()
	Muxer(host string) (hostMux *pat.HostMux, err error)
	Override(host string) string
	HostChecks() (hostChecksJSON string, err error)
	RunMode() string
	SetRunMode(string)
	Unblock(user string)
}
