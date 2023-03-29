package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	auth "bitbucket.org/_metalogic_/access-apis"
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

	// construct and validate logout URI
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

func (c *Client) loginURI() string {
	u := c.baseURL.JoinPath("/login")
	return u.String()
}

func (c *Client) loginRequest(data []byte) (req *http.Request, err error) {
	u := c.baseURL.JoinPath("/login")

	req, err = http.NewRequest("POST", u.String(), bytes.NewBuffer(data))
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) logoutURI() string {
	u := c.baseURL.JoinPath("/logout")
	return u.String()
}

func (c *Client) refreshURI(userID string) string {
	// TODO
	//
	//	u := c.baseURL.JoinPath(fmt.Sprintf("/users/%s/refresh", userID))
	u := c.baseURL.JoinPath("/refresh")
	return u.String()
}

func (c *Client) refreshRequest(jwtRefresh, uid string) (req *http.Request, err error) {
	u := c.baseURL.JoinPath("/refresh")

	req, err = http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)
	req.Header.Add("X-Jwt-Refresh", jwtRefresh)

	return req, err
}

/************************************
 * client endpoint wrapper functions
 ************************************/

func (c *Client) Login(email, password string) (a *auth.Auth, err error) {

	log.Debugf("executing tenant user %s login %s", email, c.loginURI())

	var loginData = []byte(fmt.Sprintf(`{
		"email": "%s",
		"password": "%s"
	}`, email, password))

	req, err := c.loginRequest(loginData)
	if err != nil {
		return a, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return a, err
	}
	if resp.StatusCode != http.StatusOK {
		return a, fmt.Errorf("login request to %s failed with HTTP status %d", c.loginURI(), resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return a, err
	}

	a = &auth.Auth{}
	err = json.Unmarshal(data, a)
	if err != nil {
		return a, err
	}

	return a, nil

}

// TODO should mark the user with uid as must reauthenticate (refresh token will fail)
func (c *Client) Logout(uid string) (err error) {
	return nil
}

func (c *Client) Refresh(uid, refreshToken string) (a *auth.Auth, err error) {
	log.Debugf("executing refresh request %s", c.refreshURI(uid))

	req, err := c.refreshRequest(refreshToken, uid)
	if err != nil {
		return a, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return a, err
	}
	if resp.StatusCode != http.StatusOK {
		return a, fmt.Errorf("refresh request to %s failed with HTTP status %d", c.refreshURI(uid), resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return a, err
	}

	a = &auth.Auth{}
	err = json.Unmarshal(data, a)
	if err != nil {
		return a, err
	}

	return a, nil
}
