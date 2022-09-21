package signature_test

import (
	"crypto/rand"
	"testing"

	"github.com/brave/nitriding/attestation/signature"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
)

func TestBoxVerifier_Interfaces(t *testing.T) {
	nitridingtest.AttestType[signature.Verifier](t, signature.BoxVerifier{})
}

func TestBoxVerifier_Verify(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		inputData := []byte("happy path data")

		key, err := signature.MakeBoxKeyPair()
		assert.NoError(t, err)
		signer := signature.MakeBoxSigner(key.PublicKey)

		signedDataBytes, err := signer.Sign(inputData)
		assert.NoError(t, err)

		verifier := signature.MakeBoxVerifier(key)
		outputData, err := verifier.Verify(signedDataBytes)
		assert.NoError(t, err)
		assert.Equal(t, inputData, outputData)
	})

	t.Run("bad signature", func(t *testing.T) {
		keyPair, err := signature.MakeBoxKeyPair()
		assert.NoError(t, err)

		badSignedDataBytes := make([]byte, 20)
		_, err = rand.Read(badSignedDataBytes)
		assert.NoError(t, err)

		verifier := signature.MakeBoxVerifier(keyPair)
		_, err = verifier.Verify(badSignedDataBytes)
		assert.ErrorContains(t, err, signature.ErrBadSignature)
	})
}
