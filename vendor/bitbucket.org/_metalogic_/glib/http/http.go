package http

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/_metalogic_/log"
)

type Plaintext string

type Message struct {
	Message string `json:"message"`
}

// ValidateQuery validates the query parameters of an HTTP request against a list of valid parameters'
func ValidateQuery(r *http.Request, keys ...string) error {
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

func Headers(r *http.Request) string {
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

// BoolHeader returns true if value of header is set to value, else false
func BoolHeader(r *http.Request, name, value string) bool {
	return (value == r.Header.Get(name))
}

// IntHeader returns the int value of header with name if found, else dflt
func IntHeader(r *http.Request, name string, dflt int) (int, error) {
	value := r.Header.Get(name)
	if value == "" {
		return dflt, nil
	}
	return strconv.Atoi(value)
}

// DateHeader returns the time.Time value of header with name if found, else the zero time.Time
func DateHeader(r *http.Request, name string) (t time.Time, err error) {
	value := r.Header.Get(name)
	if value == "" {
		return time.Time{}, nil
	}
	t, err = time.Parse("2006-01-02", value)
	if err != nil {
		return t, err
	}
	return t, nil
}

// DurationHeader returns the time.Time value of header with name if found, else the zero time.Time
func DurationHeader(r *http.Request, name string, dflt time.Duration) (d time.Duration, err error) {
	value := r.Header.Get(name)
	if value == "" {
		return dflt, nil
	}
	d, err = time.ParseDuration(value)
	if err != nil {
		return d, err
	}
	return d, nil
}

// StringHeader returns the string value of header with name if found, else dflt
func StringHeader(r *http.Request, name, dflt string) string {
	value := r.Header.Get(name)
	if value == "" {
		return dflt
	}
	return value
}

// TernaryHeader implements ternary header (true/false/nil) via bool pointer to implement
func TernaryHeader(r *http.Request, name string) (*bool, error) {
	var b bool
	v := r.Header.Get(name)
	switch v {
	case "":
		return nil, nil
	case "yes":
		b = true
		return &b, nil
	case "no":
		b = false
		return &b, nil
	}
	return nil, fmt.Errorf("provided bool parameter '%s' must have value 'yes' or 'no'", name)
}

// BoolParam returns true if query parameter is set to value, else false
func BoolParam(r *http.Request, name, value string) bool {
	return (value == r.URL.Query().Get(name))
}

// DateParam returns the time.Time value of query parameter with name if found, else the zero time.Time
func DateParam(r *http.Request, name string) (t time.Time, err error) {
	value := r.URL.Query().Get(name)
	if value == "" {
		return time.Time{}, nil
	}
	t, err = time.Parse("2006-01-02", value)
	if err != nil {
		return t, err
	}
	return t, nil
}

// DurationParam returns the time.Duration value of query parameter with name if found, else the zero time.Duration
func DurationParam(r *http.Request, name string, dflt time.Duration) (d time.Duration, err error) {
	value := r.URL.Query().Get(name)
	if value == "" {
		return dflt, nil
	}
	d, err = time.ParseDuration(value)
	if err != nil {
		return d, err
	}
	return d, nil
}

// IntParam returns the int value of query parameter with name if found, else dflt
func IntParam(r *http.Request, name string, dflt int) (int, error) {
	value := r.URL.Query().Get(name)
	if value == "" {
		return dflt, nil
	}
	return strconv.Atoi(value)
}

// Int64Param returns the int64 value of query parameter with name if found, else dflt
func Int64Param(r *http.Request, name string, dflt int64) (int64, error) {
	value := r.URL.Query().Get(name)
	if value == "" {
		return dflt, nil
	}
	return strconv.ParseInt(name, 10, 64)
}

// StringParam returns the string value of query parameter with name if found, else dflt
func StringParam(r *http.Request, name, dflt string) string {
	value := r.URL.Query().Get(name)
	if value == "" {
		return dflt
	}
	return value
}

// TernaryParam implements ternary query parameter :q(true/false/nil) via bool pointer to implement
func TernaryParam(r *http.Request, name string) (*bool, error) {
	var b bool
	v := r.URL.Query().Get(name)
	switch v {
	case "":
		return nil, nil
	case "yes":
		b = true
		return &b, nil
	case "no":
		b = false
		return &b, nil
	}
	return nil, fmt.Errorf("provided bool parameter '%s' must have value 'yes' or 'no'", name)
}

// OkJSON writes an HTTP status 200 OK response with body JSON
func OkJSON(w http.ResponseWriter, json string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, json)
}

// MsgJSON writes an HTTP status 200 OK response with constructed message JSON
func MsgJSON(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	json := fmt.Sprintf("{\"message\" : %s}", strconv.Quote(message))
	fmt.Fprint(w, json)
}

// ErrJSON writes an HTTP status response with constructed error message JSON and logs the error
func ErrJSON(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	e, ok := err.(*ErrorResponse)
	if !ok {
		e = NewBadRequestError(err.Error())
	}
	http.Error(w, e.JSON(), e.Status)
	if e.Status == 404 {
		log.Warning(e.Error())
	} else {
		log.Error(e.Error())
	}
}

// OkText writes an HTTP status 200 OK response with plain text body
func OkText(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, text)
}

// ErrText writes an HTTP status response with constructed error message text and logs the error
func ErrText(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	e, ok := err.(*ErrorResponse)
	if !ok {
		e = NewBadRequestError(err.Error())
	}
	http.Error(w, e.Text(), e.Status)
	if e.Status == 404 {
		log.Warning(e.Error())
	} else {
		log.Error(e.Error())
	}
}

// OkXML writes an HTTP status 200 OK response with body XML
func OkXML(w http.ResponseWriter, xml string) {
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, xml)
}
