package server

//lint:file-ignore ST1001 dot import avoids package prefix in reference

import (
	"encoding/json"
	"net/http"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http"
)

// @Tags ACS endpoints
// @Summary returns the defined host groups in an access control system
// @Description returns the defined host groups in an access control system
// @ID get-hostgroups
// @Produce  json
// @Param body body fauth.HostGroup true "host group"
// @Success 200 {string} ok
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /forward-auth/v1/hostgroups [post]
func HostGroups(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		hostChecks, err := db.HostGroups()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

// @Tags ACS endpoints
// @Summary creates a new host group in an access control system
// @Description creates a new host group in an access control system
// @ID create-hostgroup
// @Produce  json
// @Success 200 {string} ok
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /forward-auth/v1/hostgroups [get]
func CreateHostGroup(userHeader string, store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		sessionGUID := StringHeader(r, userHeader, rootGUID)

		decoder := json.NewDecoder(r.Body)
		var group fauth.HostGroup

		// unmarshal JSON into &answers
		err = decoder.Decode(&group)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = group.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := db.CreateHostGroup(sessionGUID, group)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func HostGroup(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		hostChecks, err := db.HostGroup(groupGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func UpdateHostGroup(userHeader string, store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]

		decoder := json.NewDecoder(r.Body)
		var group fauth.HostGroup

		// unmarshal JSON body into &group
		err = decoder.Decode(&group)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = group.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := db.UpdateHostGroup(sessionGUID, groupGUID, group)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func DeleteHostGroup(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		hostChecks, err := db.DeleteHostGroup(groupGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func Hosts(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		hostChecks, err := db.Hosts(groupGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func CreateHost(userHeader string, store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]

		decoder := json.NewDecoder(r.Body)
		var host fauth.Host

		// unmarshal JSON body into &group
		err = decoder.Decode(&host)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = host.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := db.CreateHost(sessionGUID, groupGUID, host.Hostname)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func Host(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		hostGUID := params["hostGUID"]
		hostChecks, err := db.Host(groupGUID, hostGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func UpdateHost(userHeader string, store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]
		hostGUID := params["hostGUID"]

		decoder := json.NewDecoder(r.Body)
		var host fauth.Host

		// unmarshal JSON body into &group
		err = decoder.Decode(&host)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = host.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := db.UpdateHost(sessionGUID, groupGUID, hostGUID, host.Hostname)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func DeleteHost(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		hostGUID := params["hostGUID"]
		hostChecks, err := db.DeleteHost(groupGUID, hostGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func Checks(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		hostChecks, err := db.Checks(groupGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func CreateCheck(userHeader string, store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]

		decoder := json.NewDecoder(r.Body)
		var check fauth.Check

		// unmarshal JSON body into &group
		err = decoder.Decode(&check)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = check.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := db.CreateCheck(sessionGUID, groupGUID, check)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func Check(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]
		hostChecks, err := db.Check(groupGUID, checkGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func UpdateCheck(userHeader string, store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]

		decoder := json.NewDecoder(r.Body)
		var check fauth.Check

		// unmarshal JSON body into &group
		err = decoder.Decode(&check)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = check.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := db.UpdateCheck(sessionGUID, groupGUID, checkGUID, check)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func DeleteCheck(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]
		hostChecks, err := db.DeleteCheck(groupGUID, checkGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func Paths(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]

		pathsJSON, err := db.Paths(groupGUID, checkGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, pathsJSON)
	}
}

func CreatePath(userHeader string, store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]

		decoder := json.NewDecoder(r.Body)
		var path fauth.Path
		// unmarshal JSON body into &group
		err = decoder.Decode(&path)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = path.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		pathJSON, err := db.CreatePath(sessionGUID, groupGUID, checkGUID, path)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, pathJSON)
	}
}

func Path(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]
		pathGUID := params["pathGUID"]
		pathJSON, err := db.Path(groupGUID, checkGUID, pathGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, pathJSON)
	}
}

func UpdatePath(userHeader string, store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]
		pathGUID := params["pathGUID"]
		decoder := json.NewDecoder(r.Body)
		var path fauth.Path
		// unmarshal JSON body into &group
		err = decoder.Decode(&path)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = path.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		pathJSON, err := db.UpdatePath(sessionGUID, groupGUID, checkGUID, pathGUID, path)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, pathJSON)
	}
}
func DeletePath(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		db, err := store.Database()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]
		pathGUID := params["pathGUID"]
		hostChecks, err := db.DeletePath(groupGUID, checkGUID, pathGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}
