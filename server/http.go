package server

import (
	"fmt"
	"net/http"
)

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
