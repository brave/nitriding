package nitridingtest

import (
	"errors"
	"regexp"
	"runtime"
	"strings"
)

func ErrorMatchesPattern(err error, regexStrs ...string) (bool, error) {
	if err == nil {
		return false, errors.New("'err' parameter is nil")
	}

	for _, regex := range regexStrs {
		matches, err := regexp.MatchString(regex, err.Error())
		if err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func ReflectTestName() string {
	pc := make([]uintptr, 1)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	components := strings.Split(f.Name(), ".")
	return components[len(components)-1]
}
