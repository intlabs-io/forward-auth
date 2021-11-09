package fauth

// AccessControls ...
type AccessControls struct {
	Overrides  map[string]string `json:"overrides,omitempty"`
	HostGroups []HostGroup       `json:"hostGroups"`
}

// Host ...
type Host struct {
	Hostname string `json:"hostname"`
}

// HostGroup associates a set of checks with hosts to which they apply
type HostGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	GUID        string   `json:"guid"`
	Hosts       []string `json:"hosts"`
	Default     string   `json:"default"` // "allow" or "deny" (define in pat?)
	Checks      []Check  `json:"checks"`
}

// Check defines a base URI and the paths below to which access rules are applie
type Check struct {
	GUID        string `json:"guid"`
	Description string `json:"description,omitempty"`
	Name        string `json:"name"`
	Base        string `json:"base"`
	Version     int    `json:"version"`
	Paths       []Path `json:"paths"`
}

// Method is an HTTP method: GET, POST, PUT, ...
type Method string

// Path associates a path with its list of access rules
type Path struct {
	Path  string          `json:"path"`
	Rules map[Method]Rule `json:"rules"`
}

// Rule ...
type Rule struct {
	Description string `json:"description"`
	Expression  string `json:"expression"`
}
