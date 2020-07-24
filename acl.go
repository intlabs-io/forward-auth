package fauth

// HostACLs ...
type HostACLs struct {
	Hosts   []string `json:"hosts"`
	Default bool     `json:"default"`
	ACLs    []ACL    `json:"acls"`
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
	Expression  string `json:"expression"`
}
