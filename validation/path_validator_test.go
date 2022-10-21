package validation_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/brave/nitriding/nitridingtest"
	"github.com/brave/nitriding/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileValidator_Interfaces(t *testing.T) {
	validator := validation.FileValidator{}
	nitridingtest.AttestType[validation.PathValidator](t, validator)
}

func TestMakeFileValidator_Validate(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		fv := validation.MakeFileValidator(validation.FilePathRegex)
		err := fv.Validate("ok_file_name")
		assert.NoError(t, err)
	})

	tests := map[string]struct {
		fileName string
		errRegex string
	}{
		"invalid fileName": {
			fileName: " ",
			errRegex: "file name not valid",
		},
		"no such file": {
			fileName: "0/0",
			errRegex: "open .* no such file",
		},
		"fileName too long": {
			fileName: strings.Repeat("0", 256),
			errRegex: "open .* too long",
		},
		"permission denied": {
			fileName: "/0",
			errRegex: "open .* permission denied",
		},
	}

	fv := validation.MakeFileValidator(validation.FilePathRegex)

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := fv.Validate(tc.fileName)
			require.Error(t, err)
			assert.Regexp(t, regexp.MustCompile(tc.errRegex), err.Error())
		})
	}
}

// NOTE: This test uses global (file) state and cannot run on multiple workers
// Run it with go test -fuzz=FuzzFileValidator_Validate -parallel=1
func FuzzFileValidator_Validate(f *testing.F) {
	tests := []struct {
		fileName string
	}{
		{" "},                      // file name not valid
		{"0/0"},                    // no such file or directory
		{strings.Repeat("0", 256)}, // file name too long
		{"/0"},                     // permission denied
	}
	for _, tc := range tests {
		f.Add(tc.fileName)
	}

	fv := validation.MakeFileValidator(validation.FilePathRegex)

	f.Fuzz(func(t *testing.T, fileName string) {
		validateErr := fv.Validate(fileName)
		if validateErr != nil {
			ok, err := nitridingtest.ErrorMatchesPattern(
				validateErr,
				"file name not valid",
				"open .* no such file",
				"open .* too long",
				"open .* permission denied",
			)
			assert.NoError(t, err)
			assert.Truef(t, ok, "file name '%v' err: %v", fileName, validateErr)
		}
	})
}
