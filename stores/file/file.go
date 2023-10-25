package file

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	_ "embed"

	authz "bitbucket.org/_metalogic_/authorize"
	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	"github.com/fsnotify/fsnotify"
)

//go:embed base.json
var base []byte

// FileStore implements the forward-auth file storage interface
type FileStore struct {
	directory string
	access    string
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

	access, err := getFile(dir)
	if err != nil {
		log.Fatal(err)
	}

	store = &FileStore{
		directory: dir,
		access:    access,
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
func (store *FileStore) Load() (acs *authz.AccessSystem, err error) {

	acs = &authz.AccessSystem{}

	acs, err = load(store)

	if err != nil {
		return acs, err
	}

	log.Debugf("loaded access control system: %+v", acs)

	return acs, nil
}

// load acs from store
func load(store *FileStore) (acs *authz.AccessSystem, err error) {

	// execute base template;
	// we use template.HTML rather than string to avoid Go template escaping single quotes
	type ForwardAuth struct {
		Host          template.HTML
		ClientAppKeys template.HTML
	}

	host := config.MustGetConfig("FORWARD_AUTH_HOST")
	clientAppKeys := config.MustGetConfig("CLIENT_APP_KEYS") // eg "ACME_ADMIN_APP_KEY,ACME_FINANCE_APP_KEY"
	fa := &ForwardAuth{
		Host:          template.HTML(host),
		ClientAppKeys: template.HTML(quoteCSV(clientAppKeys)),
	}

	// Create a new template from base
	tpl, err := template.New("base").Parse(string(base))
	if err != nil {
		return acs, fmt.Errorf("error creating template: %s", err)
	}

	// Create a buffer to hold the parsed template
	buf := new(bytes.Buffer)

	// Execute the template and write the output to the buffer
	err = tpl.Execute(buf, fa)
	if err != nil {
		return acs, err
	}

	// load the templated base Access Control System

	acs = &authz.AccessSystem{}

	err = json.Unmarshal(buf.Bytes(), acs)
	if err != nil {
		return acs, err
	}

	o, err := json.Marshal((acs))
	if err != nil {
		log.Fatal("base marshaled to invalid ACS")
	}

	log.Debugf("loaded base ACS: %s", o)

	// publicKeys maps tenantIDs to their publicKeys; forward-auth uses the tenant public key
	// to verify request signatures signed with the corresponding private key of the tenant
	acs.PublicKeys = make(map[string]string, 0)

	// tokens maps bearer tokens to token names that are used to express conditions in access rules; the map contains
	// mappings of token values to tenant IDs and application names:
	//   |  TOKEN  |  Tenant ID  (the tenant ID to which the token is assigned)
	//   |  TOKEN  |  Application Token Name  | (the application token name that is authorized to use the token)
	//
	acs.Tokens = make(map[string]string, 0)

	err = loadTokens(acs, acs.Tokens, acs.PublicKeys)
	if err != nil {
		return acs, err
	}

	// load the application Access Control System
	data, err := readFile(store.access)
	if err != nil {
		return acs, err
	}

	access := &authz.AccessSystem{}

	err = json.Unmarshal(data, access)
	if err != nil {
		return acs, err
	}

	log.Debugf("loaded access ACS from '%s': %+v", store.access, access)

	owner := access.Owner
	if owner.Bearer == nil {
		return acs, fmt.Errorf("owner root key is undefined")
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

	acs.Owner = owner

	err = loadTokens(access, acs.Tokens, acs.PublicKeys)
	if err != nil {
		return acs, err
	}

	loadChecks(access.Authorization, acs)
	return acs, nil
}

func loadTokens(acs *authz.AccessSystem, tokens map[string]string, publicKeys map[string]string) error {
	for _, application := range acs.Applications {
		// map application bearer token value to name
		if application.Bearer != nil {
			switch application.Bearer.Source {
			case "database":
				// TODO
			case "env":
				if !application.Bearer.Optional {
					tokens[config.MustGetConfig(application.Bearer.Name)] = application.Bearer.Name
				}
			case "file":
				tokens[application.Bearer.Value] = application.Bearer.Name
			default:
				return fmt.Errorf("invalid bearer token source for application %s: %s", application.Name, application.Bearer.Source)
			}
		}
	}

	for _, tenant := range acs.Tenants {
		// map tenant bearer token value to tenant ID
		if tenant.Bearer != nil {
			switch tenant.Bearer.Source {
			case "database":
				// TODO
			case "env":
				if !tenant.Bearer.Optional {
					tokens[config.MustGetConfig(tenant.Bearer.Name)] = tenant.UUID
				}
			case "file":
				value := tenant.Bearer.Value
				if value == "" {
					return fmt.Errorf("bearer token value is empty")
				}
				tokens[value] = tenant.UUID
			default:
				return fmt.Errorf("invalid bearer token source for tenant %s: %s", tenant.Name, tenant.Bearer.Source)
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
					return fmt.Errorf("public key value is empty")
				}
				publicKeys[tenant.UUID] = tenant.PublicKey.Value
			case "url":
				// TODO
			default:
				return fmt.Errorf("invalid public key source: %s", tenant.PublicKey.Source)
			}
		}
	}
	return nil
}

func loadChecks(checks *authz.Authorization, acs *authz.AccessSystem) {
	acs.Authorization.GroupChecks = append(acs.Authorization.GroupChecks, checks.GroupChecks...)

	for k, v := range checks.Overrides {
		acs.Authorization.Overrides[k] = v
	}
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

func readFile(file string) (data []byte, err error) {
	data, err = os.ReadFile(file)
	if err != nil {
		return data, err
	}
	return data, nil
}

func getFile(dir string) (access string, err error) {

	access = filepath.Join(dir, "access.json")
	if e, err := exists(access); err != nil {
		return access, err
	} else if !e {
		return access, fmt.Errorf("%s does not exist", access)
	}

	return access, nil
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

func quoteCSV(input string) (output string) {
	// Split the input string by commas
	elements := strings.Split(input, ",")

	// Trim leading and trailing spaces from each element
	for i, element := range elements {
		elements[i] = strings.TrimSpace(element)
	}

	// Build the output string with single quotes around each element
	output = "'" + strings.Join(elements, "','") + "'"

	return output
}
