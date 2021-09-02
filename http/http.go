package http

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	. "bitbucket.org/_metalogic_/glib/http" // dot import fo avoid package prefix in reference (shutup lint)
	"bitbucket.org/_metalogic_/log"
)

func validateQuery(r *http.Request, keys ...string) error {
	for key := range r.URL.Query() {
		found := false
		for _, valid := range keys {
			log.Tracef("testing parameter %s against %s", key, valid)
			if key == valid {
				found = true
				continue
			}
		}
		if !found {
			return NewBadRequestError("invalid parameter '" + key + "'")
		}
	}
	return nil
}

func stringParam(r *http.Request, name, dflt string) string {
	value := r.URL.Query().Get(name)
	if value == "" {
		return dflt
	}
	return value
}

func boolParam(r *http.Request, name, value string) bool {
	return (value == r.URL.Query().Get(name))
}

func intParam(r *http.Request, name string, dflt int) (int, error) {
	value := r.URL.Query().Get(name)
	if value == "" {
		return dflt, nil
	}
	return strconv.Atoi(value)
}

func msgJSONList(w http.ResponseWriter, list []string) {
	w.Header().Set("Content-Type", "application/json")
	json := fmt.Sprintf("{\"message\" : \"%v\"}", list)
	fmt.Fprint(w, json)
}

func tstJSON(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	json := fmt.Sprintf("{\"status\" : %d, \"message\" : \"%s\"}", status, message)
	http.Error(w, json, http.StatusPreconditionRequired)
}

func headers(r *http.Request) string {
	var h string
	// Loop over header names
	for name, values := range r.Header {
		// Loop over all values for the name.
		for _, value := range values {
			h = h + fmt.Sprintf("%s : %s; ", name, strings.ReplaceAll(strings.ReplaceAll(value, "\"", ""), "\n", ""))
		}
	}
	return strings.Trim(h, " ")
}

// returns true if key has given value in paramMap
func checkQuery(paramMap map[string][]string, key, value string) bool {
	if values, ok := paramMap[key]; !ok {
		return false
	} else {
		for _, v := range values {
			if v == value {
				return true
			}
		}
		return false
	}
}
