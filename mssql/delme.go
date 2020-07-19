package mssql

import (
	"net/http"
	"strings"

	"bitbucket.org/_metalogic_/config"
	"bitbucket.org/_metalogic_/forward-auth/auth"
	"bitbucket.org/_metalogic_/pat"
)

// Checks ...Checks
type Checks struct {
	allowMux   *pat.HostMux
	hostMux    *pat.HostMux
	blocklist  map[string]bool
	tokens     map[string]string
	hostChecks map[string]*pat.HostMux
}

// NewChecks ...
func NewChecks(prefix string, tokenNames []string, blockhosts []string) (checks *Checks) {
	checks = &Checks{
		tokens:     make(map[string]string),
		blocklist:  make(map[string]bool),
		hostChecks: make(map[string]*pat.HostMux),
	}
	for _, name := range tokenNames {
		v := config.MustGetConfig(name)
		checks.tokens[v] = name
	}
	// the allow hosts under forward-auth control handle their own authz
	allowMux := pat.NewHostMux(http.StatusOK)
	checks.hostChecks[platformString(prefix, "admin.educationplannerbc.ca")] = allowMux
	checks.hostChecks[platformString(prefix, "apply.educationplannerbc.ca")] = allowMux
	checks.hostChecks[platformString(prefix, "apply-admin.educationplannerbc.ca")] = allowMux
	checks.hostChecks[platformString(prefix, "mc.educationplannerbc.ca")] = allowMux
	checks.hostChecks[platformString(prefix, "oauth-demo.educationplannerbc.ca")] = allowMux
	checks.hostChecks[platformString(prefix, "signon.educationplannerbc.ca")] = allowMux
	checks.hostChecks[platformString(prefix, "sts-private.educationplannerbc.ca")] = allowMux

	// EPBC Servers for test institutions
	checks.hostChecks[platformString(prefix, "horsefly.educationplannerbc.ca")] = allowMux
	checks.hostChecks[platformString(prefix, "skookumchuck.educationplannerbc.ca")] = allowMux
	checks.hostChecks[platformString(prefix, "spuzzum.educationplannerbc.ca")] = allowMux

	var hostMux = auth.APISmux(http.StatusForbidden)
	checks.hostChecks[platformString(prefix, "apis.educationplannerbc.ca")] = hostMux
	checks.hostChecks[platformString(prefix, "apis-private.educationplannerbc.ca")] = hostMux

	return checks
}

// Checks ...
func (c *Checks) Checks(host string) *pat.HostMux {
	return c.hostChecks[host]
}

func platformString(prefix, name string) string {
	prefix = strings.ToLower(prefix)
	name = strings.ToLower(name)
	if name == "admin.educationplannerbc.ca" || name == "logs.educationplannerbc.ca" || prefix != "prd" {
		return prefix + "-" + name
	}
	return name
}
