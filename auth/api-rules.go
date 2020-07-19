package auth

import (
	"bitbucket.org/_metalogic_/pat"
)

// APImux ...
func APImux(defaultStatus int) *pat.HostMux {
	return pat.NewHostMux(defaultStatus)
}
