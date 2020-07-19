package auth

import (
	"bitbucket.org/_metalogic_/pat"
)

// Logsmux
func Logsmux(EPBCID, lcatToken string, defaultStatus int) *pat.HostMux {
	hostMux := pat.NewHostMux(defaultStatus)

	logs := hostMux.AddPrefix("", DenyHandler)

	// add rules to apply bearer auth on /ws and /wss
	tokens := []string{EPBCID, lcatToken}
	logs.Get("/ws", AnyBearerHandler(tokens, nil))
	logs.Get("/wss", AnyBearerHandler(tokens, nil))
	return hostMux
}
