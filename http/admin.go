package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	fa "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/forward-auth/build"
	. "bitbucket.org/_metalogic_/glib/http" // dot import fo avoid package prefix in reference (shutup lint)
	"bitbucket.org/_metalogic_/log"
)

var runMode string

func init() {
	runMode = "enforcing"
}

// APIInfo gets forward-auth-service info
// @Summary get forward-auth service info
// @Description get forward-auth service info, including version, log level
// @ID get-info
// @Produce json
// @Success 200 {object} fa.Info
// @Failure 400 {object} fa.BadRequestError
// @Failure 404 {object} fa.NotFoundError
// @Failure 500 {object} fa.ServerError
// @Router /forward-auth/v1/info [get]
func APIInfo(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		projectInfo, err := build.Info()
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		type runtime struct {
			ProjectInfo *build.ProjectInfo `json:"projectInfo"`
			ServiceInfo map[string]string  `json:"serviceInfo"`
			LogLevel    string             `json:"logLevel"`
		}
		rt := &runtime{
			ProjectInfo: projectInfo,
			ServiceInfo: svc.Info(),
			LogLevel:    log.GetLevel().String(),
		}

		runtimeJSON, err := json.Marshal(rt)
		if err != nil {
			ErrJSON(w, NewServerError(err.Error()))
			return
		}
		OkJSON(w, string(runtimeJSON))
		return
	}
}

// Health returns 200 ok if database is responding to pings
// @Summary check health of forward-auth service
// @Description checks health of forward-auth service, currently uses a database ping
// @ID get-health
// @Produce  plain
// @Success 200 {string} string "ok"
// @Failure 400 {object} fa.BadRequestError
// @Failure 404 {object} fa.NotFoundError
// @Failure 500 {object} fa.ServerError
// @Router /forward-auth/v1/health [get]
func Health(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "text/plain")
		err := svc.Health()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable)+fmt.Sprintf(": %s", err), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok\n")
		return
	}
}

// Stats returns API statistics (currently only DB stats)
// @Summary get forward-auth service statistics
// @Description get forward-auth service statistics, currently database stats only
// @ID get-stats
// @Produce  json
// @Success 200 {object} fa.Stats
// @Failure 400 {object} fa.BadRequestError
// @Failure 404 {object} fa.NotFoundError
// @Failure 500 {object} fa.ServerError
// @Router /forward-auth/v1/stats [get]
func Stats(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		stats := svc.Stats()
		fmt.Fprint(w, stats)
		return
	}
}

// LogLevel returns the current log level
// @Summary gets the current service log level
// @Description gets the service log level (one of Trace, Debug, Info, Warn or Error)
// @ID get-get-loglevel
// @Produce json
// @Success 200 {object} fa.Message
// @Failure 400 {object} fa.BadRequestError
// @Failure 404 {object} fa.NotFoundError
// @Failure 500 {object} fa.ServerError
// @Router /forward-auth/v1/admin/loglevel [get]
func LogLevel(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		msgJSON(w, log.GetLevel().String())
	}
}

// SetLogLevel sets the service log level
// @Summary sets the service log level
// @Description dynamically sets the service log level to one of Trace, Debug, Info, Warn or Error
// @ID get-set-loglevel
// @Accept json
// @Produce json
// @Param verbosity path string true "Log Level"
// @Success 200 {object} fa.Message
// @Failure 400 {object} fa.BadRequestError
// @Failure 404 {object} fa.NotFoundError
// @Failure 500 {object} fa.ServerError
// @Router /forward-auth/v1/admin/loglevel [put]
func SetLogLevel(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
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
			errJSON(w, NewBadRequestError(fmt.Sprintf("invalid log level: %s", verbosity)))
			return
		}

		log.SetLevel(v)
		msgJSON(w, v.String())
	}
}

// RunMode sets the mode for authorization, currently either enforcing or none
func RunMode(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		msgJSON(w, fmt.Sprintf("run mode is set to '%s'", runMode))
	}
}

// SetRunMode sets the mode for authorization, currently either enforcing or none
func SetRunMode(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		mode := params["mode"]
		mode = strings.ToLower(mode)
		msgJSON(w, fmt.Sprintf("set run mode to '%s'", runMode))
	}
}

// Blocked returns an array of blocked users
func Blocked(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		msgJSONList(w, svc.Blocked())
	}
}

// Block adds userGUID to the user blacklist
func Block(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		userGUID := params["userGUID"]
		svc.Block(userGUID)
		b := fmt.Sprintf("{ \"blocked\" : \"%s\" }", userGUID)
		msgJSON(w, b)
	}
}

// Unblock removes userGUID from the user blacklist
func Unblock(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		userGUID := params["userGUID"]
		svc.Unblock(userGUID)
		b := fmt.Sprintf("{ \"unblocked\" : \"%s\" }", userGUID)
		msgJSON(w, b)
	}
}

// Tree returns a text representation of the access tree
// TODO
func Tree(svc fa.Service) func(w http.ResponseWriter, r *http.Request, params map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		tree := ""
		msgJSON(w, tree)
	}
}
