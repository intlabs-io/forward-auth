package server

import (
	"encoding/json"
	"net/http"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http" // dot import fo avoid package prefix in reference (shutup lint)
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
func HostGroups(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		hostChecks, err := store.HostGroups()
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
func CreateHostGroup(userHeader string, store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		sessionGUID := StringHeader(r, userHeader, rootGUID)

		decoder := json.NewDecoder(r.Body)
		var group fauth.HostGroup

		// unmarshal JSON into &answers
		err := decoder.Decode(&group)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = group.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := store.CreateHostGroup(sessionGUID, group)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func HostGroup(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		hostChecks, err := store.HostGroup(groupGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func UpdateHostGroup(userHeader string, store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]

		decoder := json.NewDecoder(r.Body)
		var group fauth.HostGroup

		// unmarshal JSON body into &group
		err := decoder.Decode(&group)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = group.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := store.UpdateHostGroup(sessionGUID, groupGUID, group)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func DeleteHostGroup(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		hostChecks, err := store.DeleteHostGroup(groupGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func Hosts(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		hostChecks, err := store.Hosts(groupGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func CreateHost(userHeader string, store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]

		decoder := json.NewDecoder(r.Body)
		var host fauth.Host

		// unmarshal JSON body into &group
		err := decoder.Decode(&host)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = host.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := store.CreateHost(sessionGUID, groupGUID, host.Hostname)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func Host(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		hostGUID := params["hostGUID"]
		hostChecks, err := store.Host(groupGUID, hostGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func UpdateHost(userHeader string, store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]
		hostGUID := params["hostGUID"]

		decoder := json.NewDecoder(r.Body)
		var host fauth.Host

		// unmarshal JSON body into &group
		err := decoder.Decode(&host)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = host.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := store.UpdateHost(sessionGUID, groupGUID, hostGUID, host.Hostname)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func DeleteHost(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		hostGUID := params["hostGUID"]
		hostChecks, err := store.DeleteHost(groupGUID, hostGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func Checks(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		hostChecks, err := store.Checks(groupGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func CreateCheck(userHeader string, store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]

		decoder := json.NewDecoder(r.Body)
		var check fauth.Check

		// unmarshal JSON body into &group
		err := decoder.Decode(&check)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = check.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := store.CreateCheck(sessionGUID, groupGUID, check)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func Check(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]
		hostChecks, err := store.Check(groupGUID, checkGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func UpdateCheck(userHeader string, store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]

		decoder := json.NewDecoder(r.Body)
		var check fauth.Check

		// unmarshal JSON body into &group
		err := decoder.Decode(&check)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = check.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		hostChecks, err := store.UpdateCheck(sessionGUID, groupGUID, checkGUID, check)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func DeleteCheck(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]
		hostChecks, err := store.DeleteCheck(groupGUID, checkGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}

func Paths(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]

		pathsJSON, err := store.Paths(groupGUID, checkGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, pathsJSON)
	}
}

func CreatePath(userHeader string, store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]

		decoder := json.NewDecoder(r.Body)
		var path fauth.Path
		// unmarshal JSON body into &group
		err := decoder.Decode(&path)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = path.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		pathJSON, err := store.CreatePath(sessionGUID, groupGUID, checkGUID, path)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, pathJSON)
	}
}

func Path(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]
		pathGUID := params["pathGUID"]
		pathJSON, err := store.Path(groupGUID, checkGUID, pathGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, pathJSON)
	}
}

func UpdatePath(userHeader string, store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		sessionGUID := StringHeader(r, userHeader, rootGUID)
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]
		pathGUID := params["pathGUID"]
		decoder := json.NewDecoder(r.Body)
		var path fauth.Path
		// unmarshal JSON body into &group
		err := decoder.Decode(&path)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}

		err = path.Validate()
		if err != nil {
			ErrJSON(w, err)
			return
		}

		pathJSON, err := store.UpdatePath(sessionGUID, groupGUID, checkGUID, pathGUID, path)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, pathJSON)
	}
}
func DeletePath(store fauth.Database) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		groupGUID := params["groupGUID"]
		checkGUID := params["checkGUID"]
		pathGUID := params["pathGUID"]
		hostChecks, err := store.DeletePath(groupGUID, checkGUID, pathGUID)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, hostChecks)
	}
}
