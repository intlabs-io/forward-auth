package main

// Config holds the configuration read from the YAML file defining the environment
// and endpoints to be tested
type Config struct {
	tokens            map[string]string
	tenants           map[string]string
	AllowHosts        []string `yaml:"AllowHosts"`
	ApplicationTokens []string `yaml:"ApplicationTokens"`
	TenantTokens      []string `yaml:"TenantTokens"`
	TenantIDs         []string `yaml:"TenantIDs"`
}

// NewConfig ...
func NewConfig() (config Config) {
	config = Config{
		tokens:  make(map[string]string, 0),
		tenants: make(map[string]string, 0),
	}
	return config
}

// AddToken adds a bearer token to the config for reference in tests
// Eg AddToken("MGT_TOKEN", "<<Token>>")
func (c *Config) AddToken(name, value string) {
	c.tokens[name] = value
}

// AddTenant adds a tenant EPBCID to the config for reference in tests
// Eg AddTenant("SPUZZUM", "<<EPBCID>>")
func (c *Config) AddTenant(name, value string) {
	c.tenants[name] = value
}
