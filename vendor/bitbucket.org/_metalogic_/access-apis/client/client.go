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
	. "bitbucket.org/_metalogic_/glib/http"
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

/******************************************
 * User account URIs and Requests ...
 ******************************************/

func (c *Client) usersURI() string {
	u := c.baseURL.JoinPath("/users")
	return u.String()
}

func (c *Client) userURI(uid string) string {
	u := c.baseURL.JoinPath("/users", uid)
	return u.String()
}

func (c *Client) userRequest(uid string) (req *http.Request, err error) {

	req, err = http.NewRequest("GET", c.userURI(uid), nil)
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) usersRequest() (req *http.Request, err error) {

	req, err = http.NewRequest("GET", c.usersURI(), nil)
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) createUserRequest(data []byte) (req *http.Request, err error) {

	req, err = http.NewRequest("POST", c.usersURI(), bytes.NewBuffer(data))
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) updateUserRequest(uid string, data []byte) (req *http.Request, err error) {

	req, err = http.NewRequest("PUT", c.userURI(uid), bytes.NewBuffer(data))
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) deleteUserRequest(uid string) (req *http.Request, err error) {

	req, err = http.NewRequest("DELETE", c.userURI(uid), nil)
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

/******************************************
 * User password URIs and Requests ...
 ******************************************/
// password URI used for change/set/reset password
func (c *Client) passwordURI(uid string) string {
	u := c.baseURL.JoinPath("/users", uid, "password")
	return u.String()
}

// password reset workflow URI
func (c *Client) passwordResetURI() string {
	u := c.baseURL.JoinPath("/password-reset")
	return u.String()
}

func (c *Client) passwordResetRequest(data []byte) (req *http.Request, err error) {

	req, err = http.NewRequest("POST", c.passwordResetURI(), bytes.NewBuffer(data))
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) changePasswordRequest(uid string, data []byte) (req *http.Request, err error) {

	req, err = http.NewRequest("POST", c.passwordURI(uid), bytes.NewBuffer(data))
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

func (c *Client) setPasswordRequest(uid string, data []byte) (req *http.Request, err error) {

	req, err = http.NewRequest("PUT", c.passwordURI(uid), bytes.NewBuffer(data))
	if err != nil {
		return req, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("Authorization", "Bearer "+c.apiKey)

	return req, err
}

/*******************************
 * User account login/logout ...
 *******************************/

func (c *Client) loginURI() string {
	u := c.baseURL.JoinPath("/login")
	return u.String()
}

func (c *Client) loginRequest(data []byte) (req *http.Request, err error) {
	req, err = http.NewRequest("POST", c.loginURI(), bytes.NewBuffer(data))
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

func (c *Client) GetUsers() (u []auth.UserResponse, err error) {

	data, err := c.GetUsersRaw()
	if err != nil {
		return u, err
	}

	ur := &auth.UsersResponse{}

	err = json.Unmarshal(data, &ur)
	if err != nil {
		return u, err
	}

	return ur.Users, nil
}

func (c *Client) GetUsersRaw() (usersJSON []byte, err error) {

	log.Debugf("executing tenant get users")

	req, err := c.usersRequest()
	if err != nil {
		return usersJSON, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return usersJSON, err
	}
	if resp.StatusCode != http.StatusOK {
		return usersJSON, fmt.Errorf("get users request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
	}

	usersJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		return usersJSON, err
	}

	return usersJSON, nil
}

func (c *Client) GetUser(uid string) (u *auth.User, err error) {

	data, err := c.GetUserRaw(uid)
	if err != nil {
		return u, err
	}

	u = &auth.User{}
	err = json.Unmarshal(data, u)
	if err != nil {
		return u, err
	}

	return u, nil
}

func (c *Client) GetUserRaw(uid string) (userJSON []byte, err error) {

	log.Debugf("executing tenant get user %s", uid)

	req, err := c.userRequest(uid)
	if err != nil {
		return userJSON, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return userJSON, err
	}

	if resp.StatusCode != http.StatusOK {
		return userJSON, fmt.Errorf("get user request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
	}

	userJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		return userJSON, err
	}

	return userJSON, nil
}

func (c *Client) CreateUser(email, password string, superuser bool) (u *auth.User, err error) {

	log.Debugf("executing tenant create user %s", email)

	var userData = []byte(fmt.Sprintf(`{
		"email": "%s",
		"password": "%s",
		"superuser": "%t"
	}`, email, password, superuser))

	// Convert the byte array to an io.ReadCloser
	reader := io.NopCloser(bytes.NewReader(userData))

	data, err := c.CreateUserRaw(reader)
	if err != nil {
		return u, err
	}

	u = &auth.User{}
	err = json.Unmarshal(data, u)
	if err != nil {
		return u, err
	}

	return u, nil
}

func (c *Client) CreateUserRaw(body io.ReadCloser) (userData []byte, err error) {

	data, err := io.ReadAll(body)
	if err != nil {
		return userData, err
	}

	req, err := c.createUserRequest(data)
	if err != nil {
		return userData, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return userData, err
	}
	if resp.StatusCode != http.StatusOK {
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return userData, fmt.Errorf("create user request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		e := &ErrorResponse{}
		err = json.Unmarshal(errorData, &e)
		if err != nil {
			log.Errorf("failed to unmarshal error response %s", err)
			return userData, fmt.Errorf("create user request to %v failed with HTTP status %d", req.URL, resp.StatusCode)

		}
		return userData, fmt.Errorf("%s", e.Message)
	}

	userData, err = io.ReadAll(resp.Body)
	if err != nil {
		return userData, err
	}

	return userData, nil
}

func (c *Client) UpdateUser(uid, status, comment string, superuser bool) (u *auth.User, err error) {

	log.Debugf("executing tenant update user %s", uid)

	var userData = []byte(fmt.Sprintf(`{
		"status": "%s",
		"comment": "%s",
		"superuser": "%t"
	}`, status, comment, superuser))

	// Convert the byte array to an io.ReadCloser
	reader := io.NopCloser(bytes.NewReader(userData))

	data, err := c.UpdateUserRaw(uid, reader)
	if err != nil {
		return u, err
	}

	u = &auth.User{}
	err = json.Unmarshal(data, u)
	if err != nil {
		return u, err
	}

	return u, nil
}

func (c *Client) UpdateUserRaw(uid string, body io.ReadCloser) (userData []byte, err error) {

	data, err := io.ReadAll(body)
	if err != nil {
		return userData, err
	}

	req, err := c.updateUserRequest(uid, data)
	if err != nil {
		return userData, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return userData, err
	}
	if resp.StatusCode != http.StatusOK {
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return userData, fmt.Errorf("update user request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		return userData, fmt.Errorf("%s", string(errorData))
	}

	userData, err = io.ReadAll(resp.Body)
	if err != nil {
		return userData, err
	}

	return userData, nil
}

func (c *Client) DeleteUser(uid string) (ok bool, err error) {

	_, err = c.DeleteUserRaw(uid)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (c *Client) DeleteUserRaw(uid string) (deleteJSON []byte, err error) {

	log.Debugf("executing tenant delete user %s", uid)

	req, err := c.deleteUserRequest(uid)
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
			return deleteJSON, fmt.Errorf("delete user request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		return deleteJSON, fmt.Errorf("%s", string(errorData))
	}

	deleteJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		return deleteJSON, err
	}

	return deleteJSON, nil
}

func (c *Client) ChangePassword(uid, old, new string) (u *auth.User, err error) {

	var userData = []byte(fmt.Sprintf(`{
		"password": "%s",
		"newPassword": "%s"
	}`, old, new))

	// Convert the byte array to an io.ReadCloser
	reader := io.NopCloser(bytes.NewReader(userData))

	data, err := c.ChangePasswordRaw(uid, reader)
	if err != nil {
		return u, err
	}

	u = &auth.User{}
	err = json.Unmarshal(data, u)
	if err != nil {
		return u, err
	}

	return u, nil
}

func (c *Client) ChangePasswordRaw(uid string, body io.ReadCloser) (userJSON []byte, err error) {

	log.Debugf("executing tenant change user password %s", uid)

	data, err := io.ReadAll(body)
	if err != nil {
		return userJSON, err
	}

	req, err := c.changePasswordRequest(uid, data)
	if err != nil {
		return userJSON, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return userJSON, err
	}

	if resp.StatusCode != http.StatusOK {
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return userJSON, fmt.Errorf("change request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		return userJSON, fmt.Errorf("%s", string(errorData))
	}

	userJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		return userJSON, err
	}

	return userJSON, nil
}

func (c *Client) SetPassword(uid, new string) (u *auth.User, err error) {

	var userData = []byte(fmt.Sprintf(`{
		"password": "%s",
	}`, new))

	// Convert the byte array to an io.ReadCloser
	reader := io.NopCloser(bytes.NewReader(userData))

	data, err := c.SetPasswordRaw(uid, reader)
	if err != nil {
		return u, err
	}

	u = &auth.User{}
	err = json.Unmarshal(data, u)
	if err != nil {
		return u, err
	}

	return u, nil
}

func (c *Client) SetPasswordRaw(uid string, body io.ReadCloser) (userJSON []byte, err error) {

	log.Debugf("executing tenant set user password %s", uid)

	data, err := io.ReadAll(body)
	if err != nil {
		return userJSON, err
	}

	req, err := c.setPasswordRequest(uid, data)
	if err != nil {
		return userJSON, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return userJSON, err
	}

	if resp.StatusCode != http.StatusOK {
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return userJSON, fmt.Errorf("set password request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		return userJSON, fmt.Errorf("%s", string(errorData))
	}

	userJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		return userJSON, err
	}

	return userJSON, nil
}

func (c *Client) StartPasswordReset(email string) (u *auth.Auth, err error) {

	var userData = []byte(fmt.Sprintf(`{
		"email": "%s"
	}`, email))

	// Convert the byte array to an io.ReadCloser
	reader := io.NopCloser(bytes.NewReader(userData))

	return c.StartPasswordResetRaw(reader)
}

func (c *Client) StartPasswordResetRaw(body io.ReadCloser) (u *auth.Auth, err error) {

	log.Debugf("initiating password reset workflow")

	data, err := io.ReadAll(body)
	if err != nil {
		return u, err
	}

	req, err := c.passwordResetRequest(data)
	if err != nil {
		return u, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return u, err
	}

	if resp.StatusCode != http.StatusOK {
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return u, fmt.Errorf("start password reset request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		return u, fmt.Errorf("%s", string(errorData))
	}

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return u, err
	}

	u = &auth.Auth{}
	err = json.Unmarshal(data, u)
	if err != nil {
		return u, err
	}
	return u, nil

}

func (c *Client) ResetPassword(uid, token string) (u *auth.User, err error) {

	var userData = []byte(fmt.Sprintf(`{
		"token": "%s"
	}`, token))

	// Convert the byte array to an io.ReadCloser
	reader := io.NopCloser(bytes.NewReader(userData))

	data, err := c.ResetPasswordRaw(uid, reader)
	if err != nil {
		return u, err
	}

	u = &auth.User{}
	err = json.Unmarshal(data, u)
	if err != nil {
		return u, err
	}

	return u, nil
}

func (c *Client) ResetPasswordRaw(uid string, body io.ReadCloser) (userJSON []byte, err error) {

	log.Debugf("executing tenant user %s reset password", uid)

	data, err := io.ReadAll(body)
	if err != nil {
		return userJSON, err
	}

	req, err := c.setPasswordRequest(uid, data)
	if err != nil {
		return userJSON, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return userJSON, err
	}

	if resp.StatusCode != http.StatusOK {
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return userJSON, fmt.Errorf("reset password request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		return userJSON, fmt.Errorf("%s", string(errorData))
	}

	userJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		return userJSON, err
	}

	return userJSON, nil
}

// ========================================================================

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
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return a, fmt.Errorf("login request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		return a, fmt.Errorf("%s", string(errorData))
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
		errorData, err := io.ReadAll(resp.Body)
		if err != nil {
			return a, fmt.Errorf("refresh request to %v failed with HTTP status %d", req.URL, resp.StatusCode)
		}
		return a, fmt.Errorf("%s", string(errorData))
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
