//go:build go1.18

package build

import (
	"log"
	"runtime/debug"
	"time"
)

var Info = BuildInfo{
	Project:  "unknown",
	Version:  "unknown",
	Revision: "unknown",
}

func init() {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		log.Printf("failed to read build info")
		return
	}
	Info.Project = buildInfo.Main.Path
	Info.Command = buildInfo.Path
	for _, m := range buildInfo.Deps {
		Info.Dependencies = append(Info.Dependencies, m.Path+" ("+m.Version+")")
	}
	Info.Version = buildInfo.Main.Version
	Info.GoVersion = buildInfo.GoVersion
	var err error
	for _, kv := range buildInfo.Settings {
		switch kv.Key {
		case "vcs.revision":
			Info.Revision = kv.Value
		case "vcs.time":
			Info.LastCommit, err = time.Parse(time.RFC3339, kv.Value)
			if err != nil {
				log.Printf("error parsing time: %s", err)
			}
		case "vcs.modified":
			Info.DirtyBuild = (kv.Value == "true")
		}
	}
}
