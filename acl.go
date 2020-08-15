package fauth

// AccessControls ...
type AccessControls struct {
	Overrides  map[string]string `json:"overrides"`
	HostChecks []HostChecks      `json:"hostChecks"`
}

// Host ...
type Host struct {
	Hostname string `json:"hostname"`
}

// HostChecks ...
type HostChecks struct {
	Hosts   []string `json:"hosts"`
	Default string   `json:"default"` // "allow" or "deny" (define in pat?)
	Checks  []Check  `json:"checks"`
}

// Check ...
type Check struct {
	Name  string `json:"name"`
	Base  string `json:"base"`
	Paths []Path `json:"paths"`
}

// Method ...
type Method string

// Path ...
type Path struct {
	Path  string          `json:"path"`
	Rules map[Method]Rule `json:"rules"`
}

// Rule ...
type Rule struct {
	Description string `json:"description"`
	Expression  string `json:"expression"`
}
