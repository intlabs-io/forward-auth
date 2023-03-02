package build

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

// Runtime combines runtime information for build, service info and log level
type Runtime struct {
	BuildInfo   BuildInfo         `json:"buildInfo"`
	ServiceInfo map[string]string `json:"serviceInfo"`
	LogLevel    string            `json:"logLevel"`
}

// BuildInfo represents project build information extracted from Git and Go debug.BuildInfo
type BuildInfo struct {
	Project      string    `json:"project"`
	Command      string    `json:"command"`
	Revision     string    `json:"revision"`
	Version      string    `json:"version"`
	LastCommit   time.Time `json:"lastCommit"`
	DirtyBuild   bool      `json:"dirtyBuild"`
	GoVersion    string    `json:"goVersion"`
	Dependencies []string  `json:"dependencies"`
}

// Name returns project name
func (i *BuildInfo) Name() (s string) {
	p := strings.Split(i.Command, "/")
	if len(p) == 0 {
		return "undefined"
	}
	return p[len(p)-1]
}

func (i *BuildInfo) Built() string {
	return i.LastCommit.Format(time.RFC1123)
}

// String returns an info string
func (i *BuildInfo) String() (s string) {
	return fmt.Sprintf("%s (version %s, revision %s) built at %s)", i.Project, i.Version, i.Revision, i.Built())
}

// Format returns the string produced by executing an input template
// to support the use of environment variables in docker compose we replace
// substrings like ((FOO)) with {{.FOO}}
func (i *BuildInfo) Format(tmpl string) (s string, err error) {
	tmpl = strings.ReplaceAll(tmpl, "((", "{{.")
	tmpl = strings.ReplaceAll(tmpl, "))", "}}")

	t, err := template.New("Info").Parse(tmpl)
	if err != nil {
		return s, err
	}

	buf := new(strings.Builder)
	err = t.Execute(buf, i)
	if err != nil {
		return s, err
	}

	s = buf.String()
	if len(s) > 0 && s[0] == '"' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == '"' {
		s = s[:len(s)-1]
	}
	return s, nil
}
