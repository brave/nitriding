package signature_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/brave/nitriding/attestation/signature"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPSSSigner_Interfaces(t *testing.T) {
	nitridingtest.AttestType[signature.Signer](t, signature.PSSSigner{})
}

func TestPSSSignerBuilder_MakeSigner(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		builder := signature.PPSSignerBuilder{KeyLen: 1024}
		signer, err := builder.MakeSigner()
		assert.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("fail to generate key", func(t *testing.T) {
		builder := signature.PPSSignerBuilder{KeyLen: 0}
		signer, err := builder.MakeSigner()
		assert.ErrorContains(t, err, signature.ErrKeyGen)
		assert.Nil(t, signer)
	})
}

func makePSSSigner(t *testing.T) (*rsa.PrivateKey, signature.PSSSigner) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	signer := signature.MakePSSSigner(*privateKey)
	require.NotNil(t, signer)
	return privateKey, signer
}

func TestPSSSigner_Sign(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		inputData := []byte("some data")
		privateKey, signer := makePSSSigner(t)

		signedDataBytes, err := signer.Sign(inputData)
		assert.NoError(t, err)
		assert.NotNil(t, signedDataBytes)

		verifier := signature.MakePSSVerifier(privateKey.PublicKey)
		assert.NoError(t, err)

		outputData, err := verifier.Verify(signedDataBytes)
		assert.NoError(t, err)
		assert.Equal(t, inputData, outputData)
	})

	t.Run("no data to sign", func(t *testing.T) {
		_, signer := makePSSSigner(t)

		signedDataBytes, err := signer.Sign([]byte{})
		assert.ErrorContains(t, err, signature.ErrNoDataToSign)
		assert.Nil(t, signedDataBytes)
	})
}

func FuzzPSSSigner_Sign(f *testing.F) {
	tests := []struct {
		inputData []byte
	}{
		{[]byte("some data")}, // happy path
		{[]byte{}},            // not data to sign
	}
	for _, tc := range tests {
		f.Add(tc.inputData)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(f, err)
	require.NotNil(f, privateKey)
	signer := signature.MakePSSSigner(*privateKey)
	require.NotNil(f, signer)
	verifier := signature.MakePSSVerifier(privateKey.PublicKey)
	assert.NoError(f, err)

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

func TestPSSSigner_MarshalPublicKey(t *testing.T) {
	_, signer := makePSSSigner(t)

	bytes := signer.MarshalPublicKey()
	assert.NotNil(t, bytes)
}

func TestPSSSigner_ParsePublicKey(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		privateKey, signer := makePSSSigner(t)

		bytes := signer.MarshalPublicKey()
		require.NotNil(t, bytes)

		publicKey, err := signature.PSSSigner{}.ParsePublicKey(bytes)
		assert.NoError(t, err)
		assert.Equal(t, &privateKey.PublicKey, publicKey)
	})

	t.Run("parsing error", func(t *testing.T) {
		publicKey, err := signature.PSSSigner{}.ParsePublicKey(nil)
		assert.Error(t, err)
		assert.Nil(t, publicKey)
	})
}
