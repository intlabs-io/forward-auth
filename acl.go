package fauth

import (
	"bitbucket.org/_metalogic_/validation"
)

// AccessSystem represents a system of access objects:
//   - Blocks: a user block list
//   - Checks: a collection of host/path checks with access rules
//   - PublicKeys: mappings of public key names to key values
//   - Tokens: mappings of bearer token values to token names
//   - JWTSecretKey: the secret key used to validate user JSON Web Tokens
type AccessSystem struct {
	Blocks       map[string]bool   `json:"blocks"`
	Applications []Application     `json:"applications"`
	Tenants      []Tenant          `json:"tenants"`
	Checks       *HostChecks       `json:"authorization"`
	PublicKeys   map[string]string `json:"publicKeys"`
	Tokens       map[string]string `json:"tokens"`
	Digests      map[string]string `json:"digests"`
	RootToken    string            `json:"rootToken"`
	JWTSecretKey string            `json:"jwtSecret,omitempty"`
}

// HostChecks ...
type HostChecks struct {
	Hash       string
	Overrides  map[string]string `json:"overrides,omitempty"`
	HostGroups []HostGroup       `json:"hostGroups"`
}

// Host ...
type Host struct {
	Hostname string `json:"hostname"`
}

func (h Host) Validate() error {
	return validation.ValidateStruct(&h,
		validation.Field(&h.Hostname, validation.Required, validation.Length(3, 256)),
	)
}

// HostGroup associates a set of checks with hosts to which they apply
type HostGroup struct {
	GUID        string   `json:"guid"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Hosts       []string `json:"hosts"`
	Default     string   `json:"default"` // "allow" or "deny" (define in pat?)
	Checks      []Check  `json:"checks"`
}

func (hg HostGroup) Validate() error {
	return validation.ValidateStruct(&hg,
		validation.Field(&hg.Name, validation.Required, validation.Length(1, 32)),
		validation.Field(&hg.Description, validation.Length(0, 1024)),
		validation.Field(&hg.Default, validation.Required, validation.In("allow", "deny")),
	)
}

// Check defines a base URI and the paths below to which access rules are applied
type Check struct {
	GUID        string `json:"guid"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Base        string `json:"base"`
	Version     int    `json:"version"`
	Paths       []Path `json:"paths"`
}

func (ch Check) Validate() error {
	return validation.ValidateStruct(&ch,
		validation.Field(&ch.Name, validation.Required, validation.Length(1, 32)),
		validation.Field(&ch.Description, validation.Length(0, 256)),
		validation.Field(&ch.Base, validation.Length(0, 128)),
	)
}

// Method is an HTTP method: GET, POST, PUT, ...
type Method string

// Path associates a path with its list of access rules
type Path struct {
	Path  string          `json:"path"`
	Rules map[Method]Rule `json:"rules"`
}

func (p Path) Validate() error {
	err := validation.ValidateStruct(&p,
		validation.Field(&p.Path, validation.Required, validation.Length(1, 1024)),
		// validation.Field(&p.Rules, validation.Map(
		// 	validation.Key("DELETE"),
		// 	validation.Key("GET"),
		// 	validation.Key("HEAD"),
		// 	validation.Key("PATCH"),
		// 	validation.Key("POST"),
		// 	validation.Key("PUT"),
		// )),
	)
	if err != nil {
		return err
	}
	for _, rule := range p.Rules {
		err = validation.ValidateStruct(&rule,
			validation.Field(&rule.Description, validation.Length(0, 512)),
			validation.Field(&rule.Expression, validation.Required, validation.Length(4, 2048)))
		if err != nil {
			return err
		}
	}
	return nil
}

// Rule ...
type Rule struct {
	Description string `json:"description"`
	Expression  string `json:"expression"`
}
