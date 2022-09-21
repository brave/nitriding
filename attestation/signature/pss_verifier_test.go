package signature_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/brave/nitriding/attestation/signature"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPSSVerifier_Interfaces(t *testing.T) {
	nitridingtest.AttestType[signature.Verifier](t, signature.PSSVerifier{})
}

func TestPSSVerifier_Verify(t *testing.T) {
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

	t.Run("error unmarshalling", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		assert.NoError(t, err)

		verifier := signature.MakePSSVerifier(privateKey.PublicKey)
		_, err = verifier.Verify([]byte("not JSON"))
		assert.ErrorContains(t, err, signature.ErrUnmarshalling)
		var e *json.SyntaxError
		assert.ErrorAs(t, err, &e)
	})

	t.Run("wrong key", func(t *testing.T) {
		data := make([]byte, 20)
		_, err := rand.Read(data)
		assert.NoError(t, err)

		privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		assert.NoError(t, err)
		require.NotNil(t, privateKey)

		signer := signature.MakePSSSigner(*privateKey)
		signedDataBytes, err := signer.Sign(data)
		assert.NoError(t, err)

		privateKey, err = rsa.GenerateKey(rand.Reader, 1024)
		assert.NoError(t, err)

		verifier := signature.MakePSSVerifier(privateKey.PublicKey)
		_, err = verifier.Verify(signedDataBytes)
		assert.ErrorContains(t, err, signature.ErrVerifying)
	})

	t.Run("data signature mismatch", func(t *testing.T) {
		data := make([]byte, 20)
		_, err := rand.Read(data)
		assert.NoError(t, err)

		privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		assert.NoError(t, err)
		require.NotNil(t, privateKey)

		signer := signature.MakePSSSigner(*privateKey)
		signedDataBytes, err := signer.Sign(data)
		assert.NoError(t, err)

		var signedData signature.SignedData
		err = json.Unmarshal(signedDataBytes, &signedData)
		assert.NoError(t, err)

		data = make([]byte, 20)
		_, err = rand.Read(data)
		assert.NoError(t, err)
		signedData = signature.SignedData{Data: data, Sig: signedData.Sig}
		signedDataBytes, err = json.Marshal(signedData)
		assert.NoError(t, err)

		verifier := signature.MakePSSVerifier(privateKey.PublicKey)
		_, err = verifier.Verify(signedDataBytes)
		assert.ErrorContains(t, err, signature.ErrVerifying)
	})
}
