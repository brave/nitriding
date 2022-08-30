package validation

import (
	"fmt"
	"regexp"
)

type StringValidator interface {
	Validate(value string) error
}

type RegexStringValidator struct {
	regex string
}

func MakeRegexStringValidator(regex string) RegexStringValidator {
	return RegexStringValidator{regex}
}

func (v RegexStringValidator) Validate(value string) error {
	regexPtr, err := regexp.Compile(v.regex)
	if err != nil {
		return err
	}

	if !regexPtr.MatchString(value) {
		return fmt.Errorf(
			"value '%v' does not match the regular expression '%v'",
			value,
			v.regex,
		)
	}

	match := regexPtr.FindString(value)
	if match != value {
		return fmt.Errorf(
			"value '%v' is different than match '%v' "+
				"from regular expression '%v'",
			value,
			match,
			v.regex,
		)
	}

	return nil
}
