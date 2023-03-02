package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"bitbucket.org/_metalogic_/log"
)

// FileFromSearchPath returns first valid file in searchpath
func FileFromSearchPath(searchpath string) (file *os.File, err error) {
	for _, c := range strings.Split(searchpath, ":") {
		var f string
		f, err = filepath.Abs(c)
		if err != nil {
			log.Debug(err)
			continue
		}
		file, err := os.Open(f) // For read access.
		if err != nil {
			log.Debug(err)
			continue
		}
		var stat os.FileInfo
		stat, err = file.Stat()
		if err != nil {
			log.Debug(err)
			continue
		}
		if stat.IsDir() {
			log.Debugf("found directory '%s' in file search path '%s'", c, searchpath)
			continue
		}
		log.Debugf("found file '%s' in search path '%s'", file.Name(), searchpath)
		return file, nil
	}
	return file, fmt.Errorf("failed to get file from search path '%s'", searchpath)
}

// DirFromSearchPath returns the first valid directory in searchpath
func DirFromSearchPath(searchpath string) (dir *os.File, err error) {
	for _, c := range strings.Split(searchpath, ":") {
		var d string
		d, err = filepath.Abs(c)
		if err != nil {
			log.Debug(err)
			continue
		}
		dir, err = os.Open(d) // open directory for read access.
		if err != nil {
			log.Debug(err)
			continue
		}
		var stat os.FileInfo
		stat, err = dir.Stat()
		if err != nil {
			log.Debug(err)
			continue
		}
		if !stat.IsDir() {
			log.Debugf("found regular file '%s' in directory search path '%s'", c, searchpath)
			continue
		}
		log.Debugf("found directory '%s' in search path '%s'", dir.Name(), searchpath)
		return dir, nil
	}
	return dir, fmt.Errorf("failed to get directory from search path '%s'", searchpath)
}

// LoadFromSearchPath returns the data read from the first valid file in searchpath
func LoadFromSearchPath(file, searchpath string) (data []byte, err error) {
	for _, c := range strings.Split(searchpath, ":") {
		var configFile string
		configFile, err = filepath.Abs(c + "/" + file)
		if err != nil {
			log.Debug(err)
			continue
		}
		data, err = ioutil.ReadFile(configFile)
		if err != nil {
			log.Debug(err)
			continue
		}
		log.Debugf("loaded data from file '%s' in search path '%s'", file, searchpath)
		return data, nil
	}
	return data, fmt.Errorf("failed to load data from file '%s' in search path '%s'", file, searchpath)
}
