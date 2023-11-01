package eval

import (
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"time"

	. "bitbucket.org/_metalogic_/glib/date"
	"bitbucket.org/_metalogic_/log"
)

var (
	tspecs = []string{"2006", "2006-01", "2006-01-02", time.RFC3339, RFC3339INT, RFC3339Z}

	Builtins = map[string]ExpressionFunction{
		"ageAt":   ageAt,
		"after":   after,
		"before":  before,
		"empty":   empty,
		"next":    next,
		"notnull": notnull,
		"now":     now,
		"null":    null,
		"one":     one,
		"random":  random,
		"round":   round,
	}

	parameters = map[string]interface{}{
		"now": time.Now().UTC(),
	}
)

// after returns true if arg[0] is after arg[1] or time.Now()
var after = func(args ...interface{}) (interface{}, error) {
	var times [2]float64
	var err error
	if len(args) == 1 {
		args = append(args, time.Now())
	}
	if len(args) != 2 {
		return false, fmt.Errorf("after() expects one or two arguments")
	}
	for i, arg := range args {
		switch arg := arg.(type) {
		case *Date:
			//t := (arg).(*Date)
			if arg == nil {
				return nil, fmt.Errorf("null Date type passed as arg[%d] to after", i)
			}
			log.Debugf("got Date: %v+", arg)
			times[i] = float64(arg.DateTime().Unix())
		case *time.Time:
			//t := (arg).(*time.Time)
			log.Debugf("got *time.Time: %v+", arg)
			if arg == nil {
				return nil, fmt.Errorf("null *Time passed as arg[%d] to after", i)
			}
			times[i] = float64((*arg).Unix())
		case time.Time:
			//t := (arg).(time.Time)
			if arg.IsZero() {
				return nil, fmt.Errorf("invalid zero time passed as arg[%d]", i)
			}
			log.Debugf("got time.Time: %v+", arg)
			times[i] = float64((arg).Unix())
		case string:
			//s := arg.(string)
			log.Debugf("got string: %+v", arg)
			var t time.Time
			for _, spec := range tspecs {
				t, err = time.Parse(spec, arg)
				if err == nil && !t.IsZero() {
					break
				}
			}
			if t.IsZero() {
				log.Errorf("arg[%d] = %s failed to parse", i, arg)
				return nil, fmt.Errorf("arg[%d] %s failed to parse as RFC", i, arg)
			}
			times[i] = float64((t).Unix())
		case float64:
			//d := arg.(float64)
			log.Debugf("got float64: %+v", arg)
			times[i] = arg
		default:
			log.Debugf("Unexpected arg[%d] to after() was: %+v", i, arg)
			return nil, fmt.Errorf("unexpected arg[%d] to after() was: %+v", i, arg)
		}
	}
	log.Debugf("evaluating after(%+v, %+v)", times[0], times[1])
	return (times[0] > times[1]), nil //times[0].After(times[1]), nil
}

// TODO why is argument list being passed as first arg in astEval
func ageAt(args ...interface{}) (interface{}, error) {
	if len(args) == 1 {
		times := args[0]

		if a, ok := times.([]time.Time); ok {
			if len(a) == 2 {
				return float64(AgeAt(a[0], a[1])), nil
			}

			return nil, fmt.Errorf("0 ageAt expects []time.Time or []string of length 2")
		}
		if a, ok := times.([]string); ok {
			if len(a) == 2 {
				if t1, err := time.Parse("2006-01-02", a[0]); err == nil {
					if t2, err := time.Parse("2006-01-02", a[1]); err == nil {
						return float64(AgeAt(t1, t2)), nil
					} else {
						return nil, err
					}
				}

			} else {
				return nil, fmt.Errorf("1 ageAt expects []time.Time or []string of length 2")
			}

		}
	}
	if len(args) == 2 {
		if a1, ok := args[0].(string); ok {
			if t1, err := time.Parse("2006-01-02", a1); err == nil {
				if a2, ok := args[1].(string); ok {
					if t2, err := time.Parse("2006-01-02", a2); err == nil {
						return float64(AgeAt(t1, t2)), nil
					} else {
						return nil, err
					}
				}
				return nil, fmt.Errorf("2 ageAt expects []time.Time or []string of length 2")
			} else {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("3 ageAt expects []time.Time or []string of length 2")
		}
	}

	return nil, fmt.Errorf("4 ageAt expects []time.Time of []string or length 2")

}

func before(args ...interface{}) (interface{}, error) {
	v, err := after(args...)
	if err != nil {
		return false, err
	}
	t := v.(bool)
	return !t, err
}

func empty(args ...interface{}) (interface{}, error) {
	log.Debugf("empty: %v\n", args)
	if len(args) != 1 {
		return false, fmt.Errorf("empty() expects a single argument")
	}
	return (reflect.ValueOf(args[0]).IsZero()), nil
}

func next(args ...interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("next() requries a single Mon-dd arg")
	}

	now := time.Now()
	y := now.Year()

	switch arg := args[0].(type) {
	case string:
		//s := args[0].(string)

		ys := fmt.Sprintf("%d-%s", y, arg)

		// t, err := time.Parse(RFC3339INT, s)
		t, err := time.Parse("2006-Jan-02", ys)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		if now.After(t) {
			ys = fmt.Sprintf("%d-%s", y+1, arg)
			t, err = time.Parse("2006-Jan-02", ys)
			if err != nil {
				log.Error(err)
				return nil, err
			}
		}

		log.Debugf("parsed next as %v+", t)
		return t, nil

	default:
		log.Debugf("Unexpected arg to after(): %+v", args[0])
		return nil, fmt.Errorf("unexpected arg to after(): %+v", args[0])
	}
}

func notnull(args ...interface{}) (interface{}, error) {
	if len(args) != 1 {
		return false, fmt.Errorf("notnull() expects a single argument")
	}
	if reflect.ValueOf(args[0]).Kind() != reflect.Ptr {
		return false, fmt.Errorf("notnull() expects a reference type argument")
	}
	return (!reflect.ValueOf(args[0]).IsNil()), nil
}

func now(args ...interface{}) (interface{}, error) {
	return float64(time.Now().UTC().UnixNano()), nil
}

func null(args ...interface{}) (interface{}, error) {
	if len(args) != 1 {
		return false, fmt.Errorf("null() expects a single argument")
	}
	if reflect.ValueOf(args[0]).Kind() != reflect.Ptr {
		return false, fmt.Errorf("null() expects a reference type argument")
	}
	return (reflect.ValueOf(args[0]).IsNil()), nil
}

func one(args ...interface{}) (interface{}, error) {
	return float64(1), nil
}

func random(args ...interface{}) (interface{}, error) {
	n := int(args[0].(float64))
	return bool(Random(n)), nil
}

func round(args ...interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("round requires exactly one argument")
	}
	if n, ok := args[0].(float64); ok {
		return math.Ceil(n), nil
	}
	return nil, fmt.Errorf("round expects a float64 argument")
}

func evaluate(expr string) (result bool, err error) {

	log.Debugf("evaluating expression %s", strings.Replace(expr, "\n", " ", -1))

	expression, err := NewEvaluableExpressionWithFunctions(expr, Builtins)
	if err != nil {
		return result, err
	}

	val, err := expression.Evaluate(parameters)
	if err != nil {
		return result, err
	}

	return val.(bool), nil
}

// Random returns true about one in n times
func Random(n int) bool {
	if rand.Intn(n) == 1 {
		return true
	}
	return false
}
