package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var Module = "unknown"

type ErrorResponse struct {
	Module    string `json:"module"`
	Status    int    `json:"-"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

func (e *ErrorResponse) Code() string {
	return http.StatusText(e.Status)
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("[%d]: %s", e.Status, e.Message)
}

func (r *ErrorResponse) JSON() (j string) {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *ErrorResponse) Text() (j string) {
	return fmt.Sprintf("%s - %d", r.Message, r.Timestamp)
}

// NewBadRequestError - HTTP Status 400
func NewBadRequestError(message string) *ErrorResponse {
	return &ErrorResponse{
		Module,
		http.StatusBadRequest,
		message,
		time.Now().UnixNano(),
	}
}

// NewUnauthorizedError - HTTP Status 401
func NewUnauthorizedError(message string) *ErrorResponse {
	return &ErrorResponse{
		Module,
		http.StatusUnauthorized,
		message,
		time.Now().UnixNano(),
	}
}

// NewForbiddenError - HTTP Status 403
func NewForbiddenError(message string) *ErrorResponse {
	return &ErrorResponse{
		Module,
		http.StatusForbidden,
		message,
		time.Now().UnixNano(),
	}
}

// NewNotFoundError - HTTP Status 404
func NewNotFoundError(message string) *ErrorResponse {
	return &ErrorResponse{
		Module,
		http.StatusNotFound,
		message,
		time.Now().UnixNano(),
	}
}

// NewServerError - HTTP Status 500
func NewServerError(message string) *ErrorResponse {
	return &ErrorResponse{
		Module,
		http.StatusInternalServerError,
		message,
		time.Now().UnixNano(),
	}
}

// NewServiceUnavailableError - HTTP Status 503
func NewServiceUnavailableError(message string) *ErrorResponse {
	return &ErrorResponse{
		Module,
		http.StatusServiceUnavailable,
		message,
		time.Now().UnixNano(),
	}
}

// NewDBError - HTTP Status 500
func NewDBError(message string) *ErrorResponse {
	return &ErrorResponse{
		Module,
		http.StatusInternalServerError,
		message,
		time.Now().UnixNano(),
	}
}
