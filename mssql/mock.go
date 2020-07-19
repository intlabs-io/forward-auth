package mssql

import (
	"context"
)

const rfc339 = "2006-01-02T15:04:05Z07:00"
const jblow = "6fd1b168-7136-4356-b172-b226120359b2"

type void struct{}

var member void

type Mock struct {
	context context.Context
	version string
}

func NewMock() (mock *Mock, err error) {
	mock = &Mock{context: context.TODO(), version: "v1"}
	return mock, err
}

func (mock *Mock) Close() {
}

func (mock *Mock) Health() error {
	return nil
}

func (mock *Mock) Version() string {
	return mock.version
}
