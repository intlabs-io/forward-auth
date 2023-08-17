// Package pat implements a simple URL pattern muxer
package pat

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"bitbucket.org/_metalogic_/log"
)

// HandlerFunc makes access decisions on HTTP requests
// it is called with HTTP method, path, params mapping parameters to values
// parsed from wildcards and catch-alls in the path and query, and request headers
// The handler may use any or none of these parameters to make its access decision.
// If access should be permitted an http.StatusOK should be returned. Any other status
// returned will result in access denied.
type HandlerFunc func(method string, path string, params map[string][]string, header http.Header) (status int, message, username string)

// AllowHandler returns HTTP status OK
func AllowHandler(method string, path string, params map[string][]string, header http.Header) (status int, message, username string) {
	return http.StatusOK, fmt.Sprintf("allowed: %s '%s'", method, path), username
}

// DenyHandler returns HTTP status forbidden
func DenyHandler(method string, path string, params map[string][]string, header http.Header) (status int, message, username string) {
	return http.StatusForbidden, fmt.Sprintf("denied: %s '%s'", method, path), username
}

// NotFoundHandler returns HTTP status not found
func NotFoundHandler(method string, path string, params map[string][]string, header http.Header) (status int, message, username string) {
	return http.StatusNotFound, fmt.Sprintf("no check found for %s: '%s'", method, path), username
}

// HostMux ...
type HostMux struct {
	defaultStatus int
	prefixMuxers  map[string]*PatternMux
}

// NewAllowMux returns a new HostMux with default status http.StatusOK
func NewAllowMux() *HostMux {
	return &HostMux{
		defaultStatus: http.StatusOK,
		prefixMuxers:  make(map[string]*PatternMux)}
}

// NewDenyMux returns a new HostMux with default HTTP status http.StatusForbidden
func NewDenyMux() *HostMux {
	return &HostMux{
		defaultStatus: http.StatusForbidden,
		prefixMuxers:  make(map[string]*PatternMux)}
}

// NewHostMux returns a new HostMux with default HTTP status
func NewHostMux(status int) *HostMux {
	return &HostMux{
		defaultStatus: status,
		prefixMuxers:  make(map[string]*PatternMux)}
}

// Check matches method and URI against its routing table using the rules described above
// returning an HTTP status, message and username if any
func (h *HostMux) Check(method, rawURI string, header http.Header) (status int, message, username string) {
	for prefix, mux := range h.prefixMuxers {
		if strings.HasPrefix(rawURI, prefix) {
			log.Debugf("calling pattern muxer %+v for prefix %s", mux, prefix)
			return mux.Check(method, strings.TrimPrefix(rawURI, prefix), header)
		}
	}
	// no match for prefix
	return h.defaultStatus, fmt.Sprintf("no prefix muxer found for %s", rawURI), username
}

// AddPrefix returns a new PatternMux associated with prefix in HostMux
// For example
//
//	hostMux := NewHostMux(http.StatusForbidden)
//	p := hostMux.AddPrefix("/persons-api/v1", DenyHandler)
//	p.Get("/persons/:guid", PersonHandler)
//	hostMux.Check("GET", "/persons-api/v1/persons/CD05494B-D1EB-43B0-A10D-3679C8AFAD1B")
//
// will result in PersonHandler being called for an authorization decision
func (h *HostMux) AddPrefix(prefix string, notFound HandlerFunc) *PatternMux {
	p := New(notFound)
	h.prefixMuxers[prefix] = p
	return p
}

// PatternMux is an HTTP request multiplexer. It matches the URL of each
// incoming request against a list of registered patterns with their associated
// methods and calls the handler for the pattern that most closely matches the
// URL.
//
// Pattern matching attempts each pattern in the order in which they were
// registered.
//
// Patterns may contain literals or captures. Capture names start with a colon
// and consist of letters A-Z, a-z, _, and 0-9. The rest of the pattern
// matches literally. The portion of the URL matching each name ends with an
// occurrence of the character in the pattern immediately following the name,
// or a /, whichever comes first. It is possible for a name to match the empty
// string.
//
// Example pattern with one capture:
//
//	/hello/:name
//
// Will match:
//
//	/hello/blake
//	/hello/keith
//
// Will not match:
//
//	/hello/blake/
//	/hello/blake/foo
//	/foo
//	/foo/bar
//
// Example 2:
//
//	/hello/:name/
//
// Will match:
//
//	/hello/blake/
//	/hello/keith/foo
//	/hello/blake
//	/hello/keith
//
// Will not match:
//
//	/foo
//	/foo/bar
//
// *****
// We don't want this behavior in the matcher - rather handle rewrites before calling:
// *****
// A pattern ending with a slash will add an implicit redirect for its non-slash
// version. For example: Get("/foo/", handler) also registers
// Get("/foo", handler) as a redirect. You may override it by registering
// Get("/foo", anotherhandler) before the slash version.
//
// Retrieve the capture from the r.URL.Query().Get(":name") in a handler (note
// the colon). If a capture name appears more than once, the additional values
// are appended to the previous values (see http://golang.org/pkg/net/url/#Values)
//
// A trivial example server is:
//
//	package main
//
//	import (
//		"io"
//		"net/http"
//		"github.com/bmizerany/pat"
//		"log"
//	)
//
//	// hello world, the web server
//	func HelloServer(w http.ResponseWriter, req *http.Request) {
//		io.WriteString(w, "hello, "+req.URL.Query().Get(":name")+"!\n")
//	}
//
//	func main() {
//		m := pat.New(AllowHandler)
//		m.Get("/hello/:name", http.HandlerFunc(HelloServer))
//
//		// Register this pat with the default serve mux so that other packages
//		// may also be exported. (i.e. /debug/pprof/*)
//		http.Handle("/", m)
//		err := http.ListenAndServe(":12345", nil)
//		if err != nil {
//			log.Fatal("ListenAndServe: ", err)
//		}
//	}
//
// When "Method Not Allowed":
//
// Pat knows what methods are allowed given a pattern and a URI. For
// convenience, PatternMux will add the Allow header for requests that
// match a pattern for a method other than the method requested and set the
// Status to "405 Method Not Allowed".
//
// If the NotFound handler is set, then it is used whenever the pattern doesn't
// match the request path for the current method (and the Allow header is not
// altered).
type PatternMux struct {
	// NotFound, if set, is used whenever the request doesn't match any
	// pattern for its method. NotFound should be set before serving any
	// requests.
	NotFound HandlerFunc
	handlers map[string][]*patHandler
}

// New returns a new PatternMux with not found handler
func New(handler HandlerFunc) *PatternMux {
	return &PatternMux{
		NotFound: handler,
		handlers: make(map[string][]*patHandler)}
}

// Check matches method and URI against its routing table using the rules described above
// returning an HTTP status, message and assigned username if any
func (p *PatternMux) Check(method, rawURI string, header http.Header) (status int, message, username string) {
	u, err := url.Parse(rawURI)
	if err != nil {
		message = fmt.Sprintf("failed to parse '%s' as valid URL: %s", rawURI, err)
		log.Error(message)
		return http.StatusForbidden, message, username
	}
	var values url.Values
	for _, ph := range p.handlers[method] {
		if params, ok := ph.try(u.Path); ok {
			if len(params) > 0 {
				u.RawQuery = url.Values(params).Encode() + "&" + u.RawQuery
			}
			values, err = url.ParseQuery(u.RawQuery)
			if err != nil {
				message = fmt.Sprintf("failed to parse query '%s' as valid URL: %s", u.RawQuery, err)
				log.Error(message)
				return http.StatusForbidden, message, username
			}
			return ph.HandlerFunc(method, rawURI, values, header)
		}
	}

	if p.NotFound != nil {
		return p.NotFound(method, rawURI, values, header)
	}

	allowed := make([]string, 0, len(p.handlers))
	for meth, handlers := range p.handlers {
		if meth == method {
			continue
		}

		for _, ph := range handlers {
			if _, ok := ph.try(rawURI); ok {
				allowed = append(allowed, meth)
			}
		}
	}

	if len(allowed) == 0 {
		return http.StatusNotFound, http.StatusText(http.StatusNotFound), username
	}

	// method not allowed
	return http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed), username
}

// Head will register a pattern with a handler for HEAD requests.
func (p *PatternMux) Head(pat string, h HandlerFunc) {
	p.Add("HEAD", pat, h)
}

// Get will register a pattern with a handler for GET requests.
// It also registers pat for HEAD requests. If this needs to be overridden, use
// Head before Get with pat.
func (p *PatternMux) Get(pat string, h HandlerFunc) {
	p.Add("HEAD", pat, h)
	p.Add("GET", pat, h)
}

// Post will register a pattern with a handler for POST requests.
func (p *PatternMux) Post(pat string, h HandlerFunc) {
	p.Add("POST", pat, h)
}

// Put will register a pattern with a handler for PUT requests.
func (p *PatternMux) Put(pat string, h HandlerFunc) {
	p.Add("PUT", pat, h)
}

// Del will register a pattern with a handler for DELETE requests.
func (p *PatternMux) Del(pat string, h HandlerFunc) {
	p.Add("DELETE", pat, h)
}

// Options will register a pattern with a handler for OPTIONS requests.
func (p *PatternMux) Options(pat string, h HandlerFunc) {
	p.Add("OPTIONS", pat, h)
}

// Patch will register a pattern with a handler for PATCH requests.
func (p *PatternMux) Patch(pat string, h HandlerFunc) {
	p.Add("PATCH", pat, h)
}

// Add will register a pattern with a handler for meth requests.
func (p *PatternMux) Add(meth, pat string, h HandlerFunc) {
	p.add(meth, pat, h)
}

func (p *PatternMux) add(meth, pat string, h HandlerFunc) {
	handlers := p.handlers[meth]
	for _, p1 := range handlers {
		if p1.pat == pat {
			return // found existing pattern; do nothing
		}
	}
	handler := &patHandler{
		pat:         pat,
		HandlerFunc: h,
	}
	p.handlers[meth] = append(handlers, handler)

	// treat prefix and prefix + / as equivalent
	if len(pat) == 1 && pat[0] == '/' {
		p.add(meth, "", h)
	}
}

// Tail returns the trailing string in path after the final slash for a pat ending with a slash.
//
// Examples:
//
//	Tail("/hello/:title/", "/hello/mr/mizerany") == "mizerany"
//	Tail("/:a/", "/x/y/z")                       == "y/z"
func Tail(pat, path string) string {
	var i, j int
	for i < len(path) {
		switch {
		case j >= len(pat):
			if pat[len(pat)-1] == '/' {
				return path[i:]
			}
			return ""
		case pat[j] == ':':
			var nextc byte
			_, nextc, j = match(pat, isAlnum, j+1)
			_, _, i = match(path, matchPart(nextc), i)
		case path[i] == pat[j]:
			i++
			j++
		default:
			return ""
		}
	}
	return ""
}

type patHandler struct {
	pat string
	HandlerFunc
}

func (ph *patHandler) try(path string) (url.Values, bool) {
	p := make(url.Values)
	var i, j int
	for i < len(path) {
		switch {
		case j >= len(ph.pat):
			if ph.pat != "/" && len(ph.pat) > 0 && ph.pat[len(ph.pat)-1] == '/' {
				return p, true
			}
			return nil, false
		case ph.pat[j] == ':':
			var name, val string
			var nextc byte
			name, nextc, j = match(ph.pat, isAlnum, j+1)
			val, _, i = match(path, matchPart(nextc), i)
			escval, err := url.QueryUnescape(val)
			if err != nil {
				return nil, false
			}
			p.Add(":"+name, escval)
		case path[i] == ph.pat[j]:
			i++
			j++
		default:
			return nil, false
		}
	}
	if j != len(ph.pat) {
		return nil, false
	}
	return p, true
}

func matchPart(b byte) func(byte) bool {
	return func(c byte) bool {
		return c != b && c != '/'
	}
}

func match(s string, f func(byte) bool, i int) (matched string, next byte, j int) {
	j = i
	for j < len(s) && f(s[j]) {
		j++
	}
	if j < len(s) {
		next = s[j]
	}
	return s[i:j], next, j
}

func isAlpha(ch byte) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_'
}

func isDigit(ch byte) bool {
	return '0' <= ch && ch <= '9'
}

func isAlnum(ch byte) bool {
	return isAlpha(ch) || isDigit(ch)
}
