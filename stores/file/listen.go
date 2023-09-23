package file

import (
	authz "bitbucket.org/_metalogic_/authorize"
	"bitbucket.org/_metalogic_/log"
	"github.com/fsnotify/fsnotify"
)

// Listen listens for changes to the access control file, calling
// updateACS to refresh its caches on change
func (store *FileStore) Listen(updateACS func(*authz.AccessSystem) error) {

	go func() {
		for {
			select {
			case event, ok := <-store.watcher.Events:
				if !ok {
					return
				}
				log.Debugf("files watch: %s", event)
				if event.Name == store.access && (event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write) {
					log.Infof("access file %s has changed; reloading", event.Name)
					acs, err := store.Load()
					if err != nil {
						log.Errorf("error reloading %s: %s", event.Name, err)
					}
					updateACS(acs)
				}
			case err, ok := <-store.watcher.Errors:
				if !ok {
					return
				}
				log.Error(err)
			}
		}
	}()
}
