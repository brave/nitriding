package validation_test

import (
	"testing"

	"github.com/blocky/nitriding/validation"
	"github.com/stretchr/testify/assert"
)

func TestBaseParamValidator_Validate(t *testing.T) {
	tests := map[string]struct {
		value   string
		regex   string
		wantErr string
	}{
		"happy path":             {"abcd12", "[a-f0-9]{6}", ""},
		"empty value":            {"", "", ""},
		"regex does not compile": {"abcd", "?", "error parsing"},
		"no match":               {"XXXXXX", "[a-f0-9]{6}", "does not match"},
		"value too short":        {"ab", "[a-f0-9]{6}", "does not match"},
		"value too long":         {"abcd1234", "[a-f0-9]{6}", "is different"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validation.MakeRegexStringValidator(tc.regex).Validate(tc.value)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}
