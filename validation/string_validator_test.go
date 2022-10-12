package validation_test

import (
	"testing"

	"github.com/brave/nitriding/nitridingtest"
	"github.com/brave/nitriding/validation"
	"github.com/stretchr/testify/assert"
)

func TestRegexStringValidator_Interfaces(t *testing.T) {
	validator := validation.RegexStringValidator{}
	nitridingtest.AttestType[validation.StringValidator](t, validator)
}

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