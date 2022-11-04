package attestation_test

import (
	"testing"

	"github.com/brave/nitriding/attestation"
	"github.com/brave/nitriding/certificate"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandaloneChecker_Interfaces(t *testing.T) {
	checker := attestation.StandaloneChecker{}
	nitridingtest.AssertType[attestation.Checker](t, checker)
}

func TestStandaloneChecker_CheckAttestDoc(t *testing.T) {
	nonce := nitridingtest.MakeRandBytes(t, 20)
	userData := nitridingtest.MakeRandBytes(t, 512)
	publicKey := nitridingtest.MakeRandBytes(t, 1024)

	attestCert, err := certificate.BasePrivilegedCertBuilder{}.Build()
	require.NoError(t, err)
	require.NotNil(t, attestCert)

	attester, err := attestation.MakeStandaloneAttester(attestCert)
	assert.NoError(t, err)
	require.NotNil(t, attester)

	attestDoc, err := attester.GetAttestDoc(nonce, publicKey, userData)
	assert.NoError(t, err)
	require.NotNil(t, attestDoc)

	checker := attestation.StandaloneChecker{}

	t.Run("happy path", func(t *testing.T) {
		result, err := checker.CheckAttestDoc(attestDoc)
		assert.NoError(t, err)

		assert.Equal(t, nonce, result.Document.Nonce)
		assert.Equal(t, publicKey, result.Document.PublicKey)
		assert.Equal(t, userData, result.Document.UserData)
	})

	t.Run("nil attestation document", func(t *testing.T) {
		result, err := checker.CheckAttestDoc(nil)
		assert.ErrorContains(t, err, attestation.ErrDocVerify)
		assert.Nil(t, result)
	})

	t.Run("empty attestation document", func(t *testing.T) {
		result, err := checker.CheckAttestDoc(attestation.CBOR{})
		assert.ErrorContains(t, err, attestation.ErrDocVerify)
		assert.Nil(t, result)
	})
}
