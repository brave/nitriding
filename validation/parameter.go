package validation

import (
	"encoding/hex"
	"fmt"
)

const ErrDecode = "could not decode param"

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

	bytes, err := hex.DecodeString(paramString)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrDecode, err)
	}
	return bytes, nil
}
