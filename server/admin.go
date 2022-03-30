package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"bitbucket.org/_metalogic_/build"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	. "bitbucket.org/_metalogic_/glib/http" // dot import fo avoid package prefix in reference (shutup lint)
	_ "bitbucket.org/_metalogic_/glib/types"
	"bitbucket.org/_metalogic_/log"
)

var runMode string

func init() {
	runMode = "enforcing"
}

// @Tags Common endpoints
// @Summary get forward-auth service info
// @Description get forward-auth service info, including version, log level
// @ID get-info
// @Produce json
// @Success 200 {object} build.Runtime
// @Failure 400 {object} ErrorResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /info [get]
func APIInfo(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {

		rt := &build.Runtime{
			BuildInfo:   build.Info,
			ServiceInfo: store.Info(),
			LogLevel:    log.GetLevel().String(),
		}

		runtimeJSON, err := json.Marshal(rt)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, string(runtimeJSON))
	}
}

// @Tags Common endpoints
// @Summary check health of forward-auth service
// @Description checks health of forward-auth service, currently uses a database ping
// @ID get-health
// @Produce plain
// @Success 200 {string} string "ok"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /forward-auth/v1/health [get]
func Health(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "text/plain")
		err := store.Health()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable)+fmt.Sprintf(": %s", err), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok\n")
		return
	}
}

// @Tags Common endpoints
// @Summary get forward-auth service statistics
// @Description get forward-auth service statistics, currently database stats only
// @ID get-stats
// @Produce  json
// @Success 200 {object} fauth.Stats
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /forward-auth/v1/stats [get]
func Stats(store fauth.Store) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		stats := store.Stats()
		fmt.Fprint(w, stats)
		return
	}
}

// @Tags Admin endpoints
// @Summary gets the current service log level
// @Description gets the service log level (one of Trace, Debug, Info, Warn or Error)
// @ID get-loglevel
// @Produce json
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /forward-auth/v1/admin/loglevel [get]
func LogLevel() func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		MsgJSON(w, log.GetLevel().String())
	}
}

// @Tags Admin endpoints
// @Summary sets the service log level
// @Description dynamically sets the service log level to one of Trace, Debug, Info, Warn or Error
// @ID set-loglevel
// @Produce json
// @Param verbosity path string true "Log Level"
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /forward-auth/v1/admin/loglevel [put]
func SetLogLevel() func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		var (
			verbosity string
		)

		verbosity = params["verbosity"]
		verbosity = strings.ToLower(verbosity)

		var v log.Level
		switch verbosity {
		case "error":
			v = log.ErrorLevel
		case "info":
			v = log.InfoLevel
		case "debug":
			v = log.DebugLevel
		case "trace":
			v = log.TraceLevel
		default:
			ErrJSON(w, NewBadRequestError(fmt.Sprintf("invalid log level: %s", verbosity)))
			return
		}

		log.SetLevel(v)
		MsgJSON(w, v.String())
	}
}

// @Summary gets the mode for authorization, currently either enforcing or none
// @Description sets the mode for authorization, currently either enforcing or none
// @ID set-runmode
// @Produce json
// @Param verbosity path string true "Log Level"
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func RunMode() func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		MsgJSON(w, fmt.Sprintf("run mode is set to '%s'", runMode))
	}
}

// @Tags Admin endpoints
// @Summary sets the run mode for authorization, currently either enforcing or none
// @Description sets the run mode for authorization, currently either enforcing or none
// @ID set-runmode
// @Produce json
// @Param verbosity path string true "Log Level"
// @Success 200 {object} types.Message
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
func SetRunMode() func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		mode := params["mode"]
		runMode = strings.ToLower(mode)
		MsgJSON(w, fmt.Sprintf("run mode is set to '%s'", runMode))
	}
}
