package env

import (
	"errors"
	"fmt"
	"reflect"
)

// Vars encapsulates input and output key/value environment mappings
type Vars struct {
	in  map[string]any
	out map[string]any
}

func NewVars() *Vars {
	return &Vars{
		in:  make(map[string]any),
		out: make(map[string]any),
	}
}

func (env *Vars) SetIn(key string, value any) {
	env.in[key] = value
}

func (env *Vars) SetOut(key string, value any) {
	env.out[key] = value
}

// In returns the typed value for an input key or an error if
// the mapped value is not of given type T
func In[T any](env *Vars, key string) (t T, err error) {
	value, ok := env.in[key]
	if !ok {
		return t, errors.New("key not found in environment")
	}

	value, ok = value.(T)
	if !ok {
		return t, fmt.Errorf("value is not a %v", reflect.TypeOf(t))
	}

	return value.(T), nil
}

func SetIn[T any](env *Vars, key string, value T) {
	env.in[key] = value
}

// Out returns the typed value for an output key or an error if
// the mapped value is not of given type T
func Out[T any](env *Vars, key string) (t T, err error) {
	value, ok := env.out[key]
	if !ok {
		return t, errors.New("key not found in environment")
	}

	value, ok = value.(T)
	if !ok {
		return t, fmt.Errorf("value is not a %v", reflect.TypeOf(t))
	}

	return value.(T), nil
}

func SetOut[T any](env *Vars, key string, value T) {
	env.out[key] = value
}
