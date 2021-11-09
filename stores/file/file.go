package file

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	"github.com/fsnotify/fsnotify"
)

// Store implements the forward-auth storage interface
type Store struct {
	directory string
	file      string
	watcher   *fsnotify.Watcher
}

// New creates a new forward-auth Service from file
func New(path string) (store *Store, err error) {
	// configure file change watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	err = watcher.Add(path)
	if err != nil {
		log.Fatal(err)
	}

	store = &Store{
		directory: path,
		file:      filepath.Join(path, "checks.json"),
		watcher:   watcher,
	}

	log.Debugf("initialized new %s service", store.ID())

	return store, err
}

func (store *Store) ID() string {
	return "file"
}

// Load loads access rules from a JSON checks file
func (store *Store) Load() (acs *fauth.AccessControls, err error) {
	// load checks from file
	data, err := ioutil.ReadFile(store.file)
	if err != nil {
		return acs, err
	}

	acs = &fauth.AccessControls{}
	err = json.Unmarshal(data, acs)
	if err != nil {
		return acs, err
	}

	log.Debugf("loaded access rules from '%s': %+v", store.file, acs)

	return acs, nil
}

// Close has nothing to do - file is only opened when loading/reloading
func (store *Store) Close() error {
	return store.watcher.Close()
}

// Health checks to see if the file service is available.
func (store *Store) Health() error {
	return nil
}

func (store *Store) Info() (info map[string]string) {
	return make(map[string]string)
}

func (store *Store) Stats() (stats string) {
	return stats
}
