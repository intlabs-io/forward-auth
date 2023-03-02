# README

build implements a simple library for capturing build time details, including git branch and 
commit hash and time

## Usage

import "bitbucket.org/_metalogic_/build"

This import will create a build.Info object containing build information:

```
// Info represents project build information extracted from Git and Go debug.BuildInfo
type Info struct {
	Project      string     `json:"project"`
	Command      string     `json:"command"`
	Revision     string     `json:"revision"`
	Version      string     `json:"version"`
	LastCommit   time.Time  `json:"lastCommit"`
	DirtyBuild   bool       `json:"dirtyBuild"`
	Dependencies []string   `json:"dependencies"`
	GoVersion    string     `json:"goVersion"`
}
```

The String() method may be used to print a project summary:

```
info: = build.Info
...
fmt.Printf("Project %s\n\n", info)
Project github.com/EducationPlannerBC/applications-api (version refs/heads/info, release c1ebd2bb7f1d10d0d4c1b28a9fc01c7e72616fbd) built at Thu, 23 Dec 2021 08:14:00 PST)
```
