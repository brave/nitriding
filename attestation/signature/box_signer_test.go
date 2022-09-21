package signature_test

import (
	"regexp"
	"testing"

	"github.com/brave/nitriding/attestation/signature"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoxSigner_Interfaces(t *testing.T) {
	nitridingtest.AttestType[signature.Signer](t, signature.BoxSigner{})
}

func TestBoxSigner_Sign(t *testing.T) {
	key, err := signature.MakeBoxKeyPair()
	require.NoError(t, err)
	signer := signature.MakeBoxSigner(key.PublicKey)

	t.Run("happy path", func(t *testing.T) {
		inputData := []byte("happy path data")

		signedDataBytes, err := signer.Sign(inputData)
		assert.NoError(t, err)

		verifier := signature.MakeBoxVerifier(key)
		outputData, err := verifier.Verify(signedDataBytes)
		assert.NoError(t, err)
		assert.Equal(t, inputData, outputData)
	})

	tests := map[string]struct {
		data     []byte
		errRegex string
	}{
		"nil data":   {data: nil, errRegex: signature.ErrNoDataToSign},
		"empty data": {data: []byte{}, errRegex: signature.ErrNoDataToSign},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			signedDataBytes, err := signer.Sign(tc.data)
			assert.Nil(t, signedDataBytes)
			require.Error(t, err)
			assert.Regexp(t, regexp.MustCompile(tc.errRegex), err.Error())
		})
	}
}

func FuzzBoxSigner_Sign(f *testing.F) {
	tests := []struct {
		inputData []byte
	}{
		{[]byte("some data")}, // happy path
		{[]byte{}},            // no data to sign
		{nil},                 // no data to sign
	}
	for _, tc := range tests {
		f.Add(tc.inputData)
	}

	key, err := signature.MakeBoxKeyPair()
	assert.NoError(f, err)
	signer := signature.MakeBoxSigner(key.PublicKey)
	verifier := signature.MakeBoxVerifier(key)

	f.Fuzz(func(t *testing.T, inputData []byte) {
		signedDataBytes, err := signer.Sign(inputData)
		if err != nil {
			assert.ErrorContainsf(t, err, signature.ErrNoDataToSign, err.Error())
		} else {
			outputData, err := verifier.Verify(signedDataBytes)
			assert.NoError(t, err)
			assert.Equal(t, inputData, outputData)
		}
	})
}

func TestBoxSigner_MarshalPublicKey(t *testing.T) {
	key, err := signature.MakeBoxKeyPair()
	assert.NoError(t, err)
	signer := signature.MakeBoxSigner(key.PublicKey)
	require.NotNil(t, signer)

	keyBytes := signer.MarshalPublicKey()
	assert.Equal(t, key.PublicKey.BoxKey[:], keyBytes)
}

func TestBoxSigner_ParsePublicKey(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		key, err := signature.MakeBoxKeyPair()
		assert.NoError(t, err)
		signer := signature.MakeBoxSigner(key.PublicKey)
		require.NotNil(t, signer)
		bytes := signer.MarshalPublicKey()
		assert.NotNil(t, bytes)

		keyBytes, err := signature.BoxSigner{}.ParsePublicKey(bytes)
		assert.NoError(t, err)
		assert.Equal(t, &key.PublicKey.BoxKey, keyBytes)
	})

	t.Run("wrong length", func(t *testing.T) {
		keyBytes, err := signature.BoxSigner{}.ParsePublicKey([]byte{})
		assert.ErrorContains(t, err, signature.ErrBadSliceLen)
		assert.Nil(t, keyBytes)
	})
}
