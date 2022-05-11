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
	files     *files
	watcher   *fsnotify.Watcher
}

type files struct {
	applications file
	blocks       file
	checks       file
	tenants      file
}

type file struct {
	hash string
	name string
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

	f, err := validateFiles(dir)
	if err != nil {
		log.Fatal(err)
	}

	store = &FileStore{
		directory: dir,
		files:     f,
		watcher:   watcher,
	}

	log.Debugf("initialized new %s service from %s", store.ID(), dir)

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

	// load user block list from file
	blocks, err := blocks(store.files)
	if err != nil {
		return acs, err
	}

	// load host checks from file
	checks, err := checks(store.files)
	if err != nil {
		return acs, err
	}

	// load public keys and bearer tokens from files
	keys, tokens, err := access(store.files)
	if err != nil {
		return acs, err
	}

	acs = &fauth.AccessSystem{
		Blocks:     blocks,
		Checks:     checks,
		PublicKeys: keys,
		Tokens:     tokens,
	}

	return acs, nil
}

func blocks(files *files) (blocks map[string]bool, err error) {
	// load blocks and its digest from file
	data, hash, err := readFile(files.blocks.name)
	if err != nil {
		return blocks, err
	}

	if hash == files.blocks.hash {
		return blocks, err
	}

	blocks = make(map[string]bool, 0)
	err = json.Unmarshal(data, &blocks)
	if err != nil {
		return blocks, err
	}

	log.Debugf("loaded blocks list from '%s': %+v", files.blocks, blocks)
	return blocks, nil

}

func checks(files *files) (checks *fauth.HostChecks, err error) {
	data, hash, err := readFile(files.checks.name)
	if err != nil {
		return checks, err
	}

	if hash == files.checks.hash {
		return checks, err
	}

	checks = &fauth.HostChecks{}
	err = json.Unmarshal(data, checks)
	if err != nil {
		return checks, err
	}

	log.Debugf("loaded host checks from '%s': %+v", files.checks.name, checks)
	return checks, nil
}

func access(files *files) (publicKeys map[string]string, tokens map[string]string, err error) {
	var (
		data []byte
		hash string
	)

	data, hash, err = readFile(files.tenants.name)
	if err != nil {
		return publicKeys, tokens, err
	}

	publicKeys = make(map[string]string, 0)
	tokens = make(map[string]string, 0)

	// load keys and tokens if tenants file has changed or this is the first load
	if hash != files.tenants.hash {
		tenants := make([]fauth.Tenant, 0)
		err = json.Unmarshal(data, &tenants)
		if err != nil {
			return publicKeys, tokens, err
		}

		for _, tenant := range tenants {
			// map tenant bearer token value to tenant ID
			if tenant.Bearer != nil {
				if tenant.Bearer.Source == "database" {
					// TODO
				}
				if tenant.Bearer.Source == "docker" {
					tokens[config.MustGetConfig(tenant.Bearer.Name)] = tenant.GUID
				}
				if tenant.Bearer.Source == "file" {
					tokens[tenant.Bearer.Value] = tenant.GUID
				}
			}
			// map tenant ID to tenant key(s)

			if tenant.PublicKey != nil {
				if tenant.PublicKey.Source == "database" {
					// TODO
				}
				if tenant.PublicKey.Source == "file" {
					if tenant.PublicKey.Value == "" {
						return publicKeys, tokens, fmt.Errorf("public key value is empty")
					}
					publicKeys[tenant.GUID] = tenant.PublicKey.Value
				}
				if tenant.PublicKey.Source == "url" {
					// TODO
				}
			}
		}

		log.Debugf("loaded tenants from '%s': %+v", files.tenants, tenants)
	}

	data, hash, err = readFile(files.applications.name)
	if err != nil {
		return publicKeys, tokens, err
	}

	// load tokens if applications file has changed or this is the first load
	if hash != files.applications.hash {
		applications := make([]fauth.Application, 0)
		err = json.Unmarshal(data, &applications)
		if err != nil {
			return publicKeys, tokens, err
		}

		for _, application := range applications {
			// map token value to token ID
			if application.Bearer != nil && application.Bearer.Source == "docker" {
				tokens[application.Bearer.Name] = config.MustGetConfig(application.Bearer.Name)
			}
		}

		log.Debugf("loaded tenants from '%s': %+v", files.tenants, access)
	}

	return publicKeys, tokens, nil
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

func validateFiles(dir string) (f *files, err error) {
	f = &files{
		applications: file{name: filepath.Join(dir, "applications.json")},
		blocks:       file{name: filepath.Join(dir, "blocks.json")},
		checks:       file{name: filepath.Join(dir, "checks.json")},
		tenants:      file{name: filepath.Join(dir, "tenants.json")},
	}
	if e, err := exists(f.applications.name); err != nil {
		return f, err
	} else if !e {
		return f, fmt.Errorf("%s does not exist", f.applications)
	}

	if e, err := exists(f.blocks.name); err != nil {
		return f, err
	} else if !e {
		return f, fmt.Errorf("%s does not exist", f.blocks)
	}

	if e, err := exists(f.checks.name); err != nil {
		return f, err
	} else if !e {
		return f, fmt.Errorf("%s does not exist", f.checks)
	}

	if e, err := exists(f.tenants.name); err != nil {
		return f, err
	} else if !e {
		return f, fmt.Errorf("%s does not exist", f.tenants)
	}

	return f, nil
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
