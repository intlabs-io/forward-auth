package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	auth "bitbucket.org/_metalogic_/access-apis"
	. "bitbucket.org/_metalogic_/glib/http"
	"bitbucket.org/_metalogic_/log"
)

/******************************************
 * Context URIs and Requests ...
 ******************************************/

func (c *Client) contextsURI() string {
	u := c.baseURL.JoinPath("/contexts")
	return u.String()
}

func (c *Client) contextURI(uid string) string {
	u := c.baseURL.JoinPath("/contexts", uid)
	return u.String()
}

func (c *Client) contextRequest(uid string) (req *http.Request, err error) {

	req, err = http.NewRequest("GET", c.contextURI(uid), nil)
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) contextsRequest() (req *http.Request, err error) {

	req, err = http.NewRequest("GET", c.contextsURI(), nil)
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) createContextRequest(data []byte) (req *http.Request, err error) {

	req, err = http.NewRequest("POST", c.contextsURI(), bytes.NewBuffer(data))
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) updateContextRequest(uid string, data []byte) (req *http.Request, err error) {

	req, err = http.NewRequest("PUT", c.contextURI(uid), bytes.NewBuffer(data))
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) deleteContextRequest(uid string) (req *http.Request, err error) {

	req, err = http.NewRequest("DELETE", c.contextURI(uid), nil)
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) GetContexts() (u []auth.ContextResponse, err error) {

	data, err := c.GetContextsRaw()
	if err != nil {
		return u, err
	}

	err = json.Unmarshal(data, &u)
	if err != nil {
		return u, err
	}

	return u, nil
}

func (c *Client) GetContextsRaw() (contextsJSON []byte, err error) {

	log.Debugf("executing tenant get contexts")

	req, err := c.contextsRequest()
	if err != nil {
		return contextsJSON, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return contextsJSON, err
	}
	if resp.StatusCode != http.StatusOK {
		return contextsJSON, fmt.Errorf("get contexts request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
	}

	contextsJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		return contextsJSON, err
	}

	return contextsJSON, nil
}

func (c *Client) GetContext(uid string) (u *auth.ContextResponse, err error) {

	data, err := c.GetContextRaw(uid)
	if err != nil {
		return u, err
	}

	u = &auth.ContextResponse{}
	err = json.Unmarshal(data, u)
	if err != nil {
		return u, err
	}

	return u, nil
}

func (c *Client) GetContextRaw(uid string) (contextJSON []byte, err error) {

	log.Debugf("executing tenant get context %s", uid)

	req, err := c.contextRequest(uid)
	if err != nil {
		return contextJSON, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return contextJSON, err
	}

	if resp.StatusCode != http.StatusOK {
		return contextJSON, fmt.Errorf("get context request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
	}

	contextJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		return contextJSON, err
	}

	return contextJSON, nil
}

func (c *Client) CreateContext(email, password string, supercontext bool) (u *auth.ContextResponse, err error) {

	log.Debugf("executing tenant create context %s", email)

	var contextData = []byte(fmt.Sprintf(`{
		"email": "%s",
		"password": "%s",
		"supercontext": "%t"
	}`, email, password, supercontext))

	// Convert the byte array to an io.ReadCloser
	reader := io.NopCloser(bytes.NewReader(contextData))

	data, err := c.CreateContextRaw(reader)
	if err != nil {
		return u, err
	}

	u = &auth.ContextResponse{}
	err = json.Unmarshal(data, u)
	if err != nil {
		return u, err
	}

	return u, nil
}

func (c *Client) CreateContextRaw(body io.ReadCloser) (contextData []byte, err error) {

	data, err := io.ReadAll(body)
	if err != nil {
		return contextData, err
	}

	req, err := c.createContextRequest(data)
	if err != nil {
		return contextData, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return contextData, err
	}
	if resp.StatusCode != http.StatusOK {
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return contextData, fmt.Errorf("create context request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		e := &ErrorResponse{}
		err = json.Unmarshal(errorData, &e)
		if err != nil {
			log.Errorf("failed to unmarshal error response %s", err)
			return contextData, fmt.Errorf("create context request to %v failed with HTTP status %d", req.URL, resp.StatusCode)

		}
		return contextData, fmt.Errorf("%s", e.Message)
	}

	contextData, err = io.ReadAll(resp.Body)
	if err != nil {
		return contextData, err
	}

	return contextData, nil
}

func (c *Client) UpdateContext(uid, status, comment string, supercontext bool) (u *auth.ContextResponse, err error) {

	log.Debugf("executing tenant update context %s", uid)

	var contextData = []byte(fmt.Sprintf(`{
		"status": "%s",
		"comment": "%s",
		"supercontext": "%t"
	}`, status, comment, supercontext))

	// Convert the byte array to an io.ReadCloser
	reader := io.NopCloser(bytes.NewReader(contextData))

	data, err := c.UpdateContextRaw(uid, reader)
	if err != nil {
		return u, err
	}

	u = &auth.ContextResponse{}
	err = json.Unmarshal(data, u)
	if err != nil {
		return u, err
	}

	return u, nil
}

func (c *Client) UpdateContextRaw(uid string, body io.ReadCloser) (contextData []byte, err error) {

	data, err := io.ReadAll(body)
	if err != nil {
		return contextData, err
	}

	req, err := c.updateContextRequest(uid, data)
	if err != nil {
		return contextData, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return contextData, err
	}
	if resp.StatusCode != http.StatusOK {
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return contextData, fmt.Errorf("update context request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		return contextData, fmt.Errorf("%s", string(errorData))
	}

	contextData, err = io.ReadAll(resp.Body)
	if err != nil {
		return contextData, err
	}

	return contextData, nil
}

func (c *Client) DeleteContext(uid string) (ok bool, err error) {

	_, err = c.DeleteContextRaw(uid)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (c *Client) DeleteContextRaw(uid string) (deleteJSON []byte, err error) {

	log.Debugf("executing tenant delete context %s", uid)

	req, err := c.deleteContextRequest(uid)
	if err != nil {
		return deleteJSON, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return deleteJSON, err
	}

	if resp.StatusCode != http.StatusOK {
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return deleteJSON, fmt.Errorf("delete context request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		return deleteJSON, fmt.Errorf("%s", string(errorData))
	}

	deleteJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		return deleteJSON, err
	}

	return deleteJSON, nil
}
