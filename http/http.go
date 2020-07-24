package http

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	fauth "bitbucket.org/_metalogic_/forward-auth"
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
			return fauth.NewBadRequestError("invalid parameter '" + key + "'")
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

func okJSON(w http.ResponseWriter, json string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, json)
}

func msgJSON(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	json := fmt.Sprintf("{\"message\" : \"%s\"}", message)
	fmt.Fprint(w, json)
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

func errJSON(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	json := fmt.Sprintf("{\"message\" : \"%s\", \"timestamp\" : %d}", err, time.Now().UnixNano())

	switch err.(type) {
	case *fauth.DBError, *fauth.ServerError:
		http.Error(w, json, http.StatusInternalServerError)
	case *fauth.BadRequestError:
		http.Error(w, json, http.StatusBadRequest)
	case *fauth.ForbiddenError:
		http.Error(w, json, http.StatusForbidden)
	case *fauth.NotFoundError:
		http.Error(w, json, http.StatusNotFound)
	case *fauth.UnauthorizedError:
		http.Error(w, json, http.StatusUnauthorized)
	default:
		http.Error(w, json, http.StatusBadRequest)
	}
	return
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
