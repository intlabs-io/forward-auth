package mssql

import (
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	"github.com/fsnotify/fsnotify"
)

// Listen listens for changes to the applications list,
// calling updateACS to refresh its caches on change
func (store *MSSql) Listen(updateACS func(*fauth.AccessSystem) error) {
	go func() {
		for {
			select {
			case event, ok := <-store.watcher.Events:
				if !ok {
					return
				}
				log.Debugf("files watch: %s", event)
				if event.Name == store.applications && (event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write) {
					log.Infof("applications list file %s has changed; reloading", store.applications)
					acs, err := store.Load()
					if err != nil {
						log.Errorf("error reloading applications list file: %s", err)
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
