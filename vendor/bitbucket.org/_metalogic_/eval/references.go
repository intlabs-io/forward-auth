package eval

import (
	"reflect"
	"time"

	"bitbucket.org/_metalogic_/glib/date"
)

type Function struct {
	Name    string        `json:"name"`
	Args    []string      `json:"args"`
	Returns []interface{} `json:"returns"`
}

type Reference struct {
	Name       string      `json:"name"`
	Type       string      `json:"type"`
	Nullable   bool        `json:"nullable"`
	References []Reference `json:"refs"`
}

// TODO
func MarshalJSON() {

}

// References constructs a Reference object representing the valid references for [x]
func References(name string, x interface{}) (ref Reference) {
	ref = Reference{
		Name:       name,
		References: make([]Reference, 0),
	}
	coreValue := reflect.ValueOf(x)

	var ptrResolved bool
	var methodRefs []Reference
	if coreValue.Kind() == reflect.Ptr {
		if _, ok := coreValue.Interface().(time.Time); ok {
			ref.References = append(ref.References, Reference{
				Name: name,
				Type: "datetime",
			})
		} else if _, ok := coreValue.Interface().(date.Date); ok {
			ref.References = append(ref.References, Reference{
				Name: name,
				Type: "date",
			})
		} else {

			n := coreValue.NumMethod()
			if n > 0 {

				methodRefs = make([]Reference, 0)

				for i := 0; i < n; i++ {

					method := coreValue.Type().Method(i)
					methodRefs = append(methodRefs, Reference{
						Name: method.Name,
						Type: method.Type.String(), //"method",
					})
				}
			}
		}

		ref.Nullable = true
		// resolve the pointer
		coreValue = coreValue.Elem()
		ptrResolved = true
	}

	if coreValue.Kind() != reflect.Struct {
		ref.Type = coreValue.Kind().String()
		if methodRefs != nil {
			ref.References = methodRefs
		} else {
			ref.References = nil
		}

		return ref
	}

	if coreValue.Kind() == reflect.Struct {
		ref.Type = "struct"

		n := coreValue.NumField()

		for i := 0; i < n; i++ {
			field := coreValue.Type().Field(i)
			fieldVal := coreValue.Field(i)

			if _, ok := fieldVal.Interface().(time.Time); ok {
				ref.References = append(ref.References, Reference{
					Name: field.Name,
					Type: "datetime",
				})
			} else if _, ok := fieldVal.Interface().(date.Date); ok {
				ref.References = append(ref.References, Reference{
					Name: field.Name,
					Type: "date",
				})
			} else if _, ok := fieldVal.Interface().(*time.Time); ok {
				ref.References = append(ref.References, Reference{
					Name: field.Name,
					Type: "datetime",
				})
			} else if _, ok := fieldVal.Interface().(*date.Date); ok {
				ref.References = append(ref.References, Reference{
					Name: field.Name,
					Type: "date",
				})
			} else {
				ref.References = append(ref.References, References(field.Name, fieldVal.Interface()))
			}

		}

		if !ptrResolved { // note: this means that ALL methods must be declared on the same target type (pointer or not)
			n := coreValue.NumMethod()
			if n > 0 {

				methodRefs = make([]Reference, 0)

				for i := 0; i < n; i++ {
					method := coreValue.Type().Method(i)
					methodRefs = append(methodRefs, Reference{
						Name: method.Name,
						Type: method.Type.String(),
					})
				}
			}
		}
	}

	if methodRefs != nil {
		ref.References = append(ref.References, methodRefs...)
	}
	return ref
}
