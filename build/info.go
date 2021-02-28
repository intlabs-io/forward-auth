package build

import buildInfo "bitbucket.org/_metalogic_/build"

//go:generate go run generate.go

// ProjectInfo allows extension of build.Info
type ProjectInfo struct {
	buildInfo.Info
}
