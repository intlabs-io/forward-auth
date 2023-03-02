package file

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	"github.com/fsnotify/fsnotify"
)

// FileStore implements the forward-auth file storage interface
type FileStore struct {
	directory string
	path      string
	watcher   *fsnotify.Watcher
}

// New creates a new forward-auth service from data files in directory dir
func New(dir string) (store *FileStore, err error) {
	// configure file change watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	err = watcher.Add(dir)
	if err != nil {
		log.Fatal(err)
	}

	f, err := getFile(dir)
	if err != nil {
		log.Fatal(err)
	}

	store = &FileStore{
		directory: dir,
		path:      f,
		watcher:   watcher,
	}

	log.Debugf("initialized new %s service %+v from %s", store.ID(), store, dir)

	return store, err
}

func (store *FileStore) ID() string {
	return "file"
}

func (store *FileStore) Database() (db fauth.Database, err error) {
	return db, fmt.Errorf("file storage adapter doesn't implement the database interface")
}

// Load loads the Access System from files
func (store *FileStore) Load() (acs *fauth.AccessSystem, err error) {

	acs = &fauth.AccessSystem{}

	acs, err = load(store.path)

	if err != nil {
		return acs, err
	}

	log.Debugf("loaded access control system: %+v", acs)
	return acs, nil
}

// load acs from store
func load(path string) (acs *fauth.AccessSystem, err error) {

	acs = &fauth.AccessSystem{}

	data, _, err := readFile(path)
	if err != nil {
		return acs, err
	}

	err = json.Unmarshal(data, acs)
	if err != nil {
		return acs, err
	}

	log.Debugf("loaded acs from '%s': %+v", path, acs)

	// publicKeys maps tenantIDs to their publicKeys; forward-auth uses the tenant public key
	// to verify request signatures signed with the corresponding private key of the tenant
	acs.PublicKeys = make(map[string]string, 0)

	// tokens maps bearer tokens to token names that are used to express conditions in access rules; the map contains
	// mappings of token values to tenant IDs and application names:
	//   |  TOKEN  |  Tenant ID  (the tenant ID to which the token is assigned)
	//   |  TOKEN  |  Application Token Name  | (the application token name that is authorized to use the token)
	//
	acs.Tokens = make(map[string]string, 0)

	for _, application := range acs.Applications {
		// map application bearer token value to name
		if application.Bearer != nil {
			switch application.Bearer.Source {
			case "database":
				// TODO
			case "docker":
				acs.Tokens[config.MustGetConfig(application.Bearer.Name)] = application.Bearer.Name
			case "env":
				acs.Tokens[config.MustGetConfig(application.Bearer.Name)] = application.Bearer.Name
			case "file":
				acs.Tokens[application.Bearer.Value] = application.Bearer.Name
			default:
				return acs, fmt.Errorf("invalid bearer token source for application %s: %s", application.Name, application.Bearer.Source)
			}
		}
	}

	owner := acs.Owner
	if owner.Bearer == nil {
		return acs, fmt.Errorf("owner root bearer token is undefined")
	}
	switch owner.Bearer.Source {
	case "database":
		// TODO
	case "env":
		value := config.MustGetConfig(owner.Bearer.Name)
		acs.Tokens[value] = "ROOT_KEY"
	case "file":
		value := owner.Bearer.Value
		if value == "" {
			return acs, fmt.Errorf("bearer token value is empty")
		}
		acs.Tokens[value] = "ROOT_KEY"
	default:
		return acs, fmt.Errorf("invalid bearer token source for owner %s: %s", owner.Name, owner.Bearer.Source)
	}

	for _, tenant := range acs.Tenants {
		// map tenant bearer token value to tenant ID
		if tenant.Bearer != nil {
			switch tenant.Bearer.Source {
			case "database":
				// TODO
			case "env":
				value := config.MustGetConfig(tenant.Bearer.Name)
				acs.Tokens[value] = tenant.UUID
			case "file":
				value := tenant.Bearer.Value
				if value == "" {
					return acs, fmt.Errorf("bearer token value is empty")
				}
				acs.Tokens[value] = tenant.UUID
			default:
				return acs, fmt.Errorf("invalid bearer token source for tenant %s: %s", tenant.Name, tenant.Bearer.Source)
			}
		}

		// map tenant ID to tenant key(s)
		if tenant.PublicKey != nil {
			switch tenant.PublicKey.Source {
			case "database":
				// TODO
			case "env":
				// TODO
			case "file":
				if tenant.PublicKey.Value == "" {
					return acs, fmt.Errorf("public key value is empty")
				}
				acs.PublicKeys[tenant.UUID] = tenant.PublicKey.Value
			case "url":
				// TODO
			default:
				return acs, fmt.Errorf("invalid public key source: %s", tenant.PublicKey.Source)
			}
		}
	}
	return acs, nil
}

// Close closes the file storage adapter;
// only the file watcher needs to be closed - the files themselves are only opened when loading/reloading
func (store *FileStore) Close() error {
	return store.watcher.Close()
}

// Health checks to see if the file service is available.
func (store *FileStore) Health() error {
	return nil
}

func (store *FileStore) Info() (info map[string]string) {
	return make(map[string]string)
}

func (store *FileStore) Stats() (stats string) {
	return stats
}

func readFile(file string) (data []byte, hash string, err error) {
	data, err = ioutil.ReadFile(file)
	if err != nil {
		return data, hash, err
	}
	return data, fmt.Sprintf("%x", md5.Sum(data)), nil
}

func getFile(dir string) (name string, err error) {

	name = filepath.Join(dir, "access.json")
	if e, err := exists(name); err != nil {
		return name, err
	} else if !e {
		return name, fmt.Errorf("%s does not exist", name)
	}

	return name, nil
}

func exists(name string) (bool, error) {
	_, err := os.Stat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
