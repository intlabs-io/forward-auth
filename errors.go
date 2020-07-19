package fauth

type UnauthorizedError struct {
	message string
}

func NewUnauthorizedError(message string) *UnauthorizedError {
	return &UnauthorizedError{
		message: message,
	}
}
func (e *UnauthorizedError) Error() string {
	return e.message
}

type ServerError struct {
	message string
}

func NewServerError(message string) *ServerError {
	return &ServerError{
		message: message,
	}
}
func (e *ServerError) Error() string {
	return e.message
}

type NotFoundError struct {
	message string
}

func NewNotFoundError(message string) *NotFoundError {
	return &NotFoundError{
		message: message,
	}
}
func (e *NotFoundError) Error() string {
	return e.message
}

type DBError struct {
	message string
}

func NewDBError(message string) *DBError {
	return &DBError{
		message: message,
	}
}
func (e *DBError) Error() string {
	return e.message
}

type BadRequestError struct {
	message string
}

func NewBadRequestError(message string) *BadRequestError {
	return &BadRequestError{
		message: message,
	}
}
func (e *BadRequestError) Error() string {
	return e.message
}

type ForbiddenError struct {
	message string
}

func NewForbiddenError(message string) *ForbiddenError {
	return &ForbiddenError{
		message: message,
	}
}
func (e *ForbiddenError) Error() string {
	return e.message
}
