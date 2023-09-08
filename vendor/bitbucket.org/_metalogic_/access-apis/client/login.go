package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	auth "bitbucket.org/_metalogic_/access-apis"
	authn "bitbucket.org/_metalogic_/authenticate"
)

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

	c.logger.Debug("executing tenant change user password", "uid", uid)

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

	c.logger.Debug("executing tenant set user password", "uid", uid)

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

func (c *Client) StartPasswordReset(email string) (u *authn.Auth, err error) {

	var userData = []byte(fmt.Sprintf(`{
		"email": "%s"
	}`, email))

	// Convert the byte array to an io.ReadCloser
	reader := io.NopCloser(bytes.NewReader(userData))

	return c.StartPasswordResetRaw(reader)
}

func (c *Client) StartPasswordResetRaw(body io.ReadCloser) (u *authn.Auth, err error) {

	c.logger.Debug("initiating password reset workflow")

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

	u = &authn.Auth{}
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

	c.logger.Debug("executing tenant user reset password", "uid", uid)

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

func (c *Client) Login(email, password string) (a *authn.Auth, err error) {

	c.logger.Debug("executing tenant user login", "email", email, "url", c.loginURI())

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

	a = &authn.Auth{}
	err = json.Unmarshal(data, a)
	if err != nil {
		return a, err
	}

	c.logger.Debug("login succeeded", "auth", a.JSON())

	return a, nil

}

// TODO should mark the user with uid as must reauthenticate (refresh token will fail)
func (c *Client) Logout(uid string) (err error) {
	return nil
}

func (c *Client) Refresh(uid, refreshToken string) (a *authn.Auth, err error) {
	c.logger.Debug("executing refresh request", "url", c.refreshURI(uid))

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

	a = &authn.Auth{}
	err = json.Unmarshal(data, a)
	if err != nil {
		return a, err
	}

	return a, nil
}
