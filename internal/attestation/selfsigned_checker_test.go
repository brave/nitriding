package attestation_test

import (
	"testing"

	"github.com/blocky/nitriding/internal/attestation"
	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitriding/internal/nitridingtest"
	"github.com/blocky/parlor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelfSignedChecker_Interfaces(t *testing.T) {
	checker := attestation.SelfSignedChecker{}
	parlor.AssertType[attestation.Checker](t, checker)
}

func TestSelfSignedChecker_CheckAttestDoc(t *testing.T) {
	nonce := nitridingtest.MakeRandBytes(t, 20)
	userData := nitridingtest.MakeRandBytes(t, 512)
	publicKey := nitridingtest.MakeRandBytes(t, 1024)

	attestCert, err := certificate.BasePrivilegedCertBuilder{}.Build()
	require.NoError(t, err)
	require.NotNil(t, attestCert)

	attester, err := attestation.MakeSelfSignedAttester(attestCert)
	assert.NoError(t, err)
	require.NotNil(t, attester)

	attest, err := attester.Attest(nonce, publicKey, userData)
	assert.NoError(t, err)
	require.NotNil(t, attest)

	checker := attestation.SelfSignedChecker{}

	t.Run("happy path", func(t *testing.T) {
		result, err := checker.Check(attest)
		assert.NoError(t, err)

		assert.Equal(t, nonce, result.Document.Nonce)
		assert.Equal(t, publicKey, result.Document.PublicKey)
		assert.Equal(t, userData, result.Document.UserData)
	})

	t.Run("nil attestation", func(t *testing.T) {
		result, err := checker.Check(nil)
		assert.ErrorContains(t, err, attestation.ErrDocVerify)
		assert.Nil(t, result)
	})

	t.Run("empty attestation", func(t *testing.T) {
		result, err := checker.Check([]byte{})
		assert.ErrorContains(t, err, attestation.ErrDocVerify)
		assert.Nil(t, result)
	})
}
