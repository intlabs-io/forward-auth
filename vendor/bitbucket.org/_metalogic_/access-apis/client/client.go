package client

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"bitbucket.org/_metalogic_/log"
)

// Client is a tenant client for access-apis.
//   - rootURL  - the base URL for the tenants API. For example, /tenants-api/v1.
//   - tenantID  - the ID of the tenant is used to construct all tenant API requests
//     For example /tenants-api/v1/tenants/ACME.
type Client struct {
	rootURL  string
	tenantID string
	apiKey   string
	client   *http.Client
	baseURL  *url.URL
	logger   *slog.Logger
}

// TODO add options allowing specification of custom timeout, insecure etc
func New(rootURL, tenantID, apiKey string, insecure bool, logger *slog.Logger) (client *Client, err error) {

	httpClient := &http.Client{
		Timeout: http.DefaultClient.Timeout,
	}

	if insecure {
		log.Warning("SECURE CLIENT ACCESS IS DISABLED - DO NOT DO THIS IN PRODUCTION!")
	}

	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}

	// construct and validate tenant base URI
	baseURL, err := url.Parse(fmt.Sprintf("%s/tenant-api/v1/tenants/%s", rootURL, tenantID))
	if err != nil {
		return client, err
	}

	return &Client{
		rootURL:  rootURL,
		tenantID: tenantID,
		apiKey:   apiKey,
		client:   httpClient,
		baseURL:  baseURL,
		logger:   logger,
	}, nil
}

func (c *Client) SetLogger(logger *slog.Logger) *slog.Logger {
	c.logger = logger
	return c.logger
}
