package build

import buildInfo "bitbucket.org/_metalogic_/build"

//go:generate go run generate.go

// ProjectInfo allows extension of build.Info
type ProjectInfo struct {
	buildInfo.Info
}

type Runtime struct {
	ProjectInfo *ProjectInfo      `json:"projectInfo"`
	ServiceInfo map[string]string `json:"serviceInfo"`
	LogLevel    string            `json:"logLevel"`
}
