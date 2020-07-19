package auth

import (
	"net/http"

	"bitbucket.org/_metalogic_/eval"
	fa "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/ident"
	"bitbucket.org/_metalogic_/log"
	"bitbucket.org/_metalogic_/pat"
)

/*
 * Authorization handlers
 */

// AllowHandler always allows access
func AllowHandler(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {
	log.Debugf("allowing %s %s with params %v for %s\n", method, path, paramMap, identity)
	return http.StatusOK
}

// DenyHandler always denies access
func DenyHandler(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {
	log.Debugf("denying %s %s with params %v for %s\n", method, path, paramMap, identity)
	return http.StatusForbidden
}

// AllowDeny calls each handler in sequence and allows on the first handler to allow, else denies
func AllowDeny(handlers ...pat.HandlerFunc) func(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {
	return func(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {
		for _, h := range handlers {
			if h(method, path, paramMap, identity) == http.StatusOK {
				return http.StatusOK
			}
		}
		return http.StatusForbidden
	}
}

// DenyAllow calls each handler in sequence and denies on the first handler to deny, else allows
func DenyAllow(handlers ...pat.HandlerFunc) func(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {
	return func(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {
		for _, h := range handlers {
			if h(method, path, paramMap, identity) != http.StatusOK {
				return http.StatusForbidden
			}
		}
		return http.StatusOK
	}
}

// BearerHandler allows access for bearer token if valid
func BearerHandler(token string, next pat.HandlerFunc) pat.HandlerFunc {
	return func(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {
		log.Debugf("handling %s %s with params %v for %s", method, path, paramMap, identity)

		if checkBearerAuth(identity, token) {
			return http.StatusOK
		}

		if next == nil {
			return http.StatusForbidden
		}

		return next(method, path, paramMap, identity)
	}
}

// AnyBearerHandler allows access for any valid token in a list of bearer tokens
func AnyBearerHandler(tokens []string, next pat.HandlerFunc) pat.HandlerFunc {
	return func(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {
		log.Debugf("handling %s %s with params %v for %s", method, path, paramMap, identity)

		if checkBearerAuth(identity, tokens...) {
			return http.StatusOK
		}

		if next == nil {
			return http.StatusForbidden
		}

		return next(method, path, paramMap, identity)
	}
}

// TenantHandler creates a handler for resources containing a tenant parameter binding.
// For example, for a path parameter ":tenantID" the value bound to :tenantID in the
// path "/tenants/:tenantID/addresses" is used to look up the corresponding tenant bearer token;
// and for a query parameter "ID" the value bound to ID in the query string "/tenants?ID=1234"
// is used to look up the tenant bearer token.
func TenantHandler(param string, next pat.HandlerFunc) pat.HandlerFunc {
	return func(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {

		log.Debugf("handling %s %s with params %v for %s", method, path, paramMap, identity)

		tenantID, ok := paramMap[param]
		if !ok {
			return http.StatusForbidden
		}

		// allow tenants to access their own resources via tenant bearer token (named by tenantID)
		if checkBearerAuth(identity, tenantID[0]) {
			return http.StatusOK
		}

		if next == nil {
			return http.StatusForbidden
		}

		return next(method, path, paramMap, identity)
	}
}

// TenantRoleHandler ...
func TenantRoleHandler(param string, tokens []string, token, role string, next pat.HandlerFunc) pat.HandlerFunc {
	return func(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {

		log.Debugf("handling %s %s with params %v for %s", method, path, paramMap, identity)

		tenantID, ok := paramMap[param]
		if !ok {
			return http.StatusForbidden
		}

		// allow only if identity has the required role/permission in the tenant
		if identity.Authorize(tenantID[0], role, fa.Action(method)) {
			return http.StatusOK
		}

		if next == nil {
			return http.StatusOK
		}

		return next(method, path, paramMap, identity)
	}
}

// RoleHandler ...
func RoleHandler(tenantID, role string, next pat.HandlerFunc) pat.HandlerFunc {
	return func(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {

		log.Debugf("handling %s %s with params %v for %s", method, path, paramMap, identity)

		// allow only if identity has the required role/permission in the tenant
		if identity.Authorize(tenantID, role, fa.Action(method)) {
			return http.StatusOK
		}

		if next == nil {
			return http.StatusForbidden
		}

		return next(method, path, paramMap, identity)
	}
}

// TODO: how about caching evalutations??
// var cache map[string]

// Eval ...
func Eval(expr string) pat.HandlerFunc {
	return func(method, path string, paramMap map[string][]string, identity ident.Authorizer) int {
		log.Debugf("checking: %s: %s with map %+v and identity %+v", method, path, paramMap, identity)
		if t, err := evaluate(paramMap, identity, expr); err != nil {
			return http.StatusForbidden
		} else if t {
			return http.StatusOK
		}
		return http.StatusForbidden
	}
}

func evaluate(paramMap map[string][]string, identity ident.Authorizer, expr string) (result bool, err error) {
	// define builtins
	functions := map[string]eval.ExpressionFunction{
		// return true if the value of one of the bearer tokens is valid in the environment
		// eg: bearer(ROOT, ...)
		"bearer": func(args ...interface{}) (interface{}, error) {
			var tokens []string
			for _, arg := range args {
				tokens = append(tokens, arg.(string))
			}
			return checkBearerAuth(identity, tokens...), nil
		},
		// return the binding of a path or query parameter
		// eg: param(:tenantID)
		"param": func(args ...interface{}) (interface{}, error) {
			param := args[0].(string)
			if v, ok := paramMap[param]; ok {
				return v[0], nil
			}
			return "", nil
		},
		// return true if identity has role permission in tenant
		// eg: role(epbcid(KPU),ADM,READ)
		"role": func(args ...interface{}) (interface{}, error) {
			tenantID := args[0].(string)
			role := args[1].(string)
			action := args[2].(string)
			return identity.Authorize(tenantID, role, action), nil
		},
	}

	expression, err := eval.NewEvaluableExpressionWithFunctions(expr, functions)
	if err != nil {
		log.Error(err)
		return result, err
	}

	parameters := make(map[string]interface{}, 8)
	for k, v := range paramMap {
		parameters[k] = v
	}

	parameters["EPBC_API_TOKEN"] = "733acb21-3ca3-4f54-a9b0-1d219c659d1c"

	log.Debugf("evaluating expression %s", expr)
	val, err := expression.Evaluate(parameters)
	if err != nil {
		log.Error(err)
		return result, err
	}

	return val.(bool), nil
}

// checkBearerAuth checks for valid bearer token in identity matching one of tokens
func checkBearerAuth(identity ident.Authorizer, tokens ...string) bool {
	if identity == nil {
		return false
	}
	for _, token := range tokens {
		if identity.Bearer(token) {
			log.Debugf("found bearer auth %s", token)
			return true
		}
	}
	log.Debugf("rejecting by bearer auth for accepted tokens: %v", tokens)
	return false
}
