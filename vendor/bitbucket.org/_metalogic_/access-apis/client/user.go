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
