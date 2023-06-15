package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"bitbucket.org/_metalogic_/config"
	fauth "bitbucket.org/_metalogic_/forward-auth"
	_ "bitbucket.org/_metalogic_/forward-auth/docs" // docs is generated by Swag CLI, you have to import it.
	httpSwagger "bitbucket.org/_metalogic_/httptreemux-swagger"
	"bitbucket.org/_metalogic_/log"
	"github.com/dimfeld/httptreemux/v5"
)

const rootGUID = "ROOT"

var (
	sessionName        string
	sessionMode        string
	accessRootURL      string
	accessTenantID     string
	accessAPIKey       string
	insecureSkipVerify bool
)

// AuthzServer ...
type AuthzServer struct {
	server *http.Server
	store  fauth.Store
	auth   *fauth.Auth
	info   map[string]string
}

func Start(addr, runMode, tenantParam, jwtHeader, userHeader, traceHeader string, store fauth.Store, wg *sync.WaitGroup) (svr *AuthzServer) {
	// load the access controls
	acs, err := store.Load()
	if err != nil {
		log.Fatal(err)
	}

	sessionMode = config.IfGetenv("SESSION_MODE", "COOKIE")
	if strings.ToLower(sessionMode) == "cookie" {
		sessionName = config.MustGetConfig("SESSION_COOKIE_NAME")
	}
	if strings.ToLower(sessionMode) == "header" {
		sessionName = config.MustGetConfig("SESSION_HEADER_NAME")
	}
	accessRootURL = config.IfGetenv("ACCESS_APIS_ROOT_URL", "http://access-apis-service.metalogic.svc.cluster.local:8080")
	accessTenantID = config.IfGetenv("ACCESS_APIS_TENANT_ID", "UNDEFINED")
	accessAPIKey = config.IfGetenv("ACCESS_APIS_TENANT_API_KEY", "UNDEFINED")
	insecureSkipVerify = config.IfGetBool("INSECURE_SKIP_VERIFY", false)

	// it must be available either by HTTP request or in the environment
	url := config.IfGetenv("IDENTITY_PROVIDER_PUBLIC_KEY_URL", "")
	var publicKey []byte
	if url != "" {
		publicKey, err = getPublicKey(url)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		publicKey = []byte(config.MustGetConfig("IDENTITY_PROVIDER_PUBLIC_KEY"))
	}

	// Symmetric secret key
	secretKey := []byte(config.MustGetConfig("JWT_SECRET_KEY"))
	// TODO jwtRefreshKey := []byte(config.MustGetConfig("JWT_REFRESH_SECRET_KEY"))

	auth, err := fauth.NewAuth(acs, sessionName, jwtHeader, publicKey, secretKey)
	if err != nil {
		log.Fatal(err)
	}

	// auth := fauth.NewAuth(addr)
	svr = &AuthzServer{
		server: &http.Server{
			Addr:    addr,
			Handler: router(auth, store, userHeader, traceHeader)},
		auth:  auth,
		store: store,
		info:  make(map[string]string),
	}

	log.Debugf("configured authorization environment %+v", svr)

	// listen for changes on the store
	go func() {
		defer wg.Done() // let caller know we are done cleaning up
		store.Listen(auth.UpdateFunc())
	}()

	// start the HTTP server
	go func() {
		defer wg.Done() // let main know we are done cleaning up

		// always returns ErrServerClosed on graceful close
		if err := svr.server.ListenAndServe(); err != http.ErrServerClosed {
			// unexpected error. port in use?
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// returning reference so caller can call Shutdown()
	return svr
}

// Stats returns server statistics
// TODO keep running stats of authorization request handling
func (svc *AuthzServer) Stats() string {
	js := fmt.Sprintf("{\"Requests\": %d, \"Allowed\" : %d, \"Denied\": %d}", 100, 50, 50)
	return js
}

// Shutdown does a clean shutdown of the authorization server
func (svc *AuthzServer) Shutdown(ctx context.Context) {
	svc.store.Close()
	if err := svc.server.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}
	log.Warning("shutdown Authz server")
}

// create the router for Service
func router(auth *fauth.Auth, store fauth.Store, userHeader, traceHeader string) *httptreemux.TreeMux {
	// initialize HTTP router;
	// forward-auth expects to be deployed at the root of a unique host (eg auth.example.com)

	corsFunc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			// w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie")
			// w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, HEAD, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Set("Access-Control-Allow-Methods", "*")
			w.Header().Add("Access-Control-Allow-Credentials", "true")

			next.ServeHTTP(w, r)
		})
	}

	treemux := httptreemux.New()

	treemux.UseHandler(corsFunc)

	api := treemux.NewGroup("/")

	// Common endpoints
	api.GET("/health", Health(store))
	api.GET("/info", APIInfo(store))
	api.GET("/stats", Stats(store))

	// Admin endpoints
	api.GET("/admin/loglevel", LogLevel())
	api.PUT("/admin/loglevel/:verbosity", SetLogLevel())
	api.GET("/admin/run", RunMode())
	api.PUT("/admin/run/:mode", SetRunMode())
	api.GET("/admin/tree", Tree(auth))
	api.GET("/openapi/*", httpSwagger.Handler(
		httpSwagger.URL("doc.json"), // The url pointing to API definition
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("#swagger-ui")))

	// Auth endpoints
	api.GET("/auth", Auth(auth, userHeader, traceHeader))
	api.POST("/auth/update", Update(auth, store)) // called by deployment-api broadcast to trigger update from store

	// Session endpoints
	api.OPTIONS("/login", Options())

	api.POST("/login", Login(auth))
	api.PUT("/logout", Logout(auth))
	api.PUT("/refresh", Refresh(auth))
	api.GET("/sessions", Sessions(auth))
	api.GET("/sessions/:sid", Session(auth))
	api.GET("/blocks", Blocked(auth))
	api.PUT("/blocks/:uid", Block(auth))
	api.DELETE("/blocks/:uid", Unblock(auth))

	// ACS endpoints - the file storage adapter does not implement these endpoints
	api.GET("/hostgroups", HostGroups(store))
	api.POST("/hostgroups", CreateHostGroup(userHeader, store))
	api.GET("/hostgroups/:gid", HostGroup(store))
	api.PUT("/hostgroups/:gid", UpdateHostGroup(userHeader, store))
	api.DELETE("/hostgroups/:gid", DeleteHostGroup(store))

	api.GET("/hostgroups/:gid/hosts", Hosts(store))
	api.POST("/hostgroups/:gid/hosts", CreateHost(userHeader, store))
	api.GET("/hostgroups/:gid/hosts/:hid", Host(store))
	api.PUT("/hostgroups/:gid/hosts/:hid", UpdateHost(userHeader, store))
	api.DELETE("/hostgroups/:gid/hosts/:hid", DeleteHost(store))

	api.GET("/hostgroups/:gid/checks", Checks(store))
	api.POST("/hostgroups/:gid/checks", CreateCheck(userHeader, store))
	api.GET("/hostgroups/:gid/checks/:ckid", Check(store))
	api.PUT("/hostgroups/:gid/checks/:ckid", UpdateCheck(userHeader, store))
	api.DELETE("/hostgroups/:gid/checks/:ckid", DeleteCheck(store))

	api.GET("/hostgroups/:gid/checks/:ckid/paths", Paths(store))
	api.POST("/hostgroups/:gid/checks/:ckid/paths", CreatePath(userHeader, store))
	api.GET("/hostgroups/:gid/checks/:ckid/paths/:pid", Path(store))
	api.PUT("/hostgroups/:gid/checks/:ckid/paths/:pid", UpdatePath(userHeader, store))
	api.DELETE("/hostgroups/:gid/checks/:ckid/paths/:pid", DeletePath(store))

	return treemux
}

func getPublicKey(url string) (publicKey []byte, err error) {
	log.Debugf("getting RSA public key from %s", url)
	client := &http.Client{}

	if insecureSkipVerify {
		log.Warning("InsecureSkipVerify is enabled for http.Client - DO NOT DO THIS IN PRODUCTION")
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return publicKey, fmt.Errorf("error creating request GET %s: %s", url, err)
	}

	resp, err := client.Do(r)
	if err != nil {
		return publicKey, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return publicKey, fmt.Errorf(resp.Status)
	}

	publicKey, err = io.ReadAll(resp.Body)
	if err != nil {
		return publicKey, err
	}

	return publicKey, nil
}
