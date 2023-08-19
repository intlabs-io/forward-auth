package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"

	"bitbucket.org/_metalogic_/log"
)

type Client struct {
	rootURL  string
	tenantID string
	apiKey   string
	client   *http.Client
	baseURL  *url.URL
}

// TODO add options allowing specification of custom timeout, insecure etc
func New(rootURL, tenantID, apiKey string, insecure bool) (client *Client, err error) {

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
	}, nil
}
