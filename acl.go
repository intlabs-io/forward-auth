package fauth

// HostACLs ...
type HostACLs struct {
	BaseURL string `json:"baseURL"`
	ACLs    []ACL  `json:"acls"`
}

// ACL ...
type ACL struct {
	Name  string `json:"name"`
	Root  string `json:"root"`
	Paths []Path `json:"paths"`
}

// Path ...
type Path struct {
	Path  string          `json:"path"`
	Rules map[Method]Rule `json:"rules"`
}

// Method ...
type Method string

// Rule ...
type Rule struct {
	Description string `json:"description"`
	Definition  string `json:"definition"`
}

// Request ...
type Request struct {
	Bearer   string   `json:"bearer"`
	Methods  []string `json:"methods"`
	Path     string   `json:"path"`
	Tenant   string   `json:"tenant"`
	Identity Identity `json:"identity"`
}
