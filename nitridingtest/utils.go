package nitridingtest

import (
	"crypto/rand"
	"errors"
	"reflect"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ErrNilErr = "the 'err' parameter cannot be nil"

func ErrorMatchesPattern(err error, regexStrs ...string) (bool, error) {
	if err == nil {
		return false, errors.New(ErrNilErr)
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

func MakeRandBytes(t *testing.T, len uint) []byte {
	bytes := make([]byte, len)
	_, err := rand.Read(bytes)
	require.NoError(t, err)
	return bytes
}

func AssertType[T any](t *testing.T, obj any) {
	_, ok := obj.(T)

	assert.Truef(
		t,
		ok,
		"obj of type %#v is not %v",
		obj,
		reflect.TypeOf((*T)(nil)).String()[1:],
	)
}
