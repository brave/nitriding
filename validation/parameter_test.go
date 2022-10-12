package validation_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/brave/nitriding/mocks"
	"github.com/brave/nitriding/validation"
	"github.com/stretchr/testify/assert"
)

func TestValidateAndDecode(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		value := "abcdef1234567890"
		validator := new(mocks.StringValidator)

		validator.On("Validate", value).Return(nil)

		valueBytes, err := validation.ValidateAndDecode(value, validator)
		assert.NoError(t, err)

		expBytes, err := hex.DecodeString(value)
		assert.NoError(t, err)
		assert.Equal(t, expBytes, valueBytes)

		validator.AssertExpectations(t)
	})

	t.Run("validator error", func(t *testing.T) {
		value := "abcdef1234567890"
		expErr := errors.New("expected error")

		validator := new(mocks.StringValidator)

		validator.On("Validate", value).Return(expErr)

		_, err := validation.ValidateAndDecode(value, validator)
		assert.ErrorIs(t, err, expErr)

		validator.AssertExpectations(t)
	})

	t.Run("decode error", func(t *testing.T) {
		value := "XXXX"
		validator := new(mocks.StringValidator)

		validator.On("Validate", value).Return(nil)

		_, err := validation.ValidateAndDecode(value, validator)
		assert.ErrorContains(t, err, validation.ErrDecode)

		validator.AssertExpectations(t)
	})
}