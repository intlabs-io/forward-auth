package mock

import (
	"context"
	"sync"
)

const rfc339 = "2006-01-02T15:04:05Z07:00"
const jblow = "6fd1b168-7136-4356-b172-b226120359b2"

type void struct{}

var member void

// Mock ...
type Mock struct {
	context context.Context
	lock    sync.RWMutex
	runMode string
	version string
}

func New() (mock *Mock, err error) {
	mock = &Mock{context: context.TODO(), version: "v1"}
	return mock, err
}

func (mock *Mock) Close() {
}

func (mock *Mock) Health() error {
	return nil
}

// RunMode returns the current value of RunMode
func (mock *Mock) RunMode() string {
	mock.lock.Lock()
	defer mock.lock.Unlock()
	return mock.runMode
}

// SetRunMode sets the value of RunMode
func (mock *Mock) SetRunMode(mode string) {
	mock.lock.Lock()
	defer mock.lock.Unlock()
	mock.runMode = mode
}

func (mock *Mock) Version() string {
	return mock.version
}
