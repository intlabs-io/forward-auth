package file

import (
	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/log"
	"github.com/fsnotify/fsnotify"
)

// Listen listens for changes to the access checks file calling
// update to refresh its cache on change
func (store *File) Listen(update func(*fauth.AccessControls) error) {

	go func() {
		for {
			select {
			case event, ok := <-store.watcher.Events:
				if !ok {
					return
				}
				log.Debugf("access checks file watch: %s", event)
				if event.Name == store.file && (event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write) {
					log.Infof("access rules file %s has changed; reloading", store.file)
					acs, err := store.Load()
					if err != nil {
						log.Errorf("error reloading access rules file: %s", err)
					}
					update(acs)
				}
			case err, ok := <-store.watcher.Errors:
				if !ok {
					return
				}
				log.Error(err)
			}
		}
	}()

	// err := store.watcher.Add(store.directory)
	// if err != nil {
	// 	log.Fatal(err)
	// }
}
