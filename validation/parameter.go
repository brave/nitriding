package validation

import (
	"encoding/hex"
)

func ValidateAndDecode(
	paramString string,
	validator StringValidator,
) (
	[]byte,
	error,
) {
	err := validator.Validate(paramString)
	if err != nil {
		return nil, err
	}

	return hex.DecodeString(paramString)
}
