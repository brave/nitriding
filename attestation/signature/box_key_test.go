package signature_test

import (
	"bytes"
	"testing"

	"github.com/brave/nitriding/attestation/signature"
	"github.com/stretchr/testify/assert"
)

func TestNewBoxKeyFromSlice(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		slice := bytes.Repeat([]byte{0x30}, signature.BoxKeyLen)
		boxKey, err := signature.NewBoxKeyFromSlice(slice)
		assert.NoError(t, err)
		assert.NotNil(t, boxKey)
	})

	t.Run("wrong key length", func(t *testing.T) {
		boxKey, err := signature.NewBoxKeyFromSlice(nil)
		assert.ErrorContains(t, err, signature.ErrBadSliceLen)
		assert.Nil(t, boxKey)
	})
}

func FuzzNewBoxKeyFromSlice(f *testing.F) {
	tests := []struct {
		inputBytes []byte
	}{
		{bytes.Repeat([]byte{0x30}, signature.BoxKeyLen)}, // happy path
		{bytes.Repeat([]byte{0x30}, 0)},                   // wrong length
		{nil},
	}
	for _, tc := range tests {
		f.Add(tc.inputBytes)
	}

	f.Fuzz(func(t *testing.T, inputData []byte) {
		boxKey, err := signature.NewBoxKeyFromSlice(inputData)
		if err != nil {
			assert.ErrorContainsf(t, err, signature.ErrBadSliceLen, err.Error())
		} else {
			assert.NotNil(t, boxKey)
		}
	})
}

func TestBoxKey_ToConstSlicePtr(t *testing.T) {
	slice := bytes.Repeat([]byte{0x30}, signature.BoxKeyLen)
	boxKey, err := signature.NewBoxKeyFromSlice(slice)
	assert.NoError(t, err)
	assert.NotNil(t, boxKey)

	slicePtr := boxKey.ToConstSlicePtr()
	assert.NotNil(t, slicePtr)
	assert.Equal(t, slice, slicePtr[:])
}

func TestNewBoxKeyPair(t *testing.T) {
	boxKeyPair, err := signature.MakeBoxKeyPair()
	assert.NoError(t, err)
	assert.NotEqual(t, boxKeyPair, signature.BoxKeyPair{})
}
