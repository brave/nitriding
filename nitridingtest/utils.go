package nitridingtest

import (
	"errors"
	"regexp"
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
