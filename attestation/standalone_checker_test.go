package attestation_test

import (
	"errors"
	"testing"

	"github.com/brave/nitriding/attestation"
	"github.com/brave/nitriding/certificate"
	"github.com/brave/nitriding/mocks"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandaloneChecker_Interfaces(t *testing.T) {
	checker := attestation.StandaloneChecker{}
	nitridingtest.AttestType[attestation.Checker](t, checker)
}

func TestMakeStandaloneChecker(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		cert, err := certificate.MakeBaseCertFromDerBytes(
			attestation.StandaloneAttesterCert,
		)
		require.NoError(t, err)
		require.NotNil(t, cert)

		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.NoError(t, err)
		assert.NotEqual(t, attestation.StandaloneChecker{}, checker)
	})

	t.Run("cannot get PEM bytes", func(t *testing.T) {
		cert := new(mocks.Cert)
		expErr := errors.New("expected error")

		cert.On("PemBytes").Return(certificate.PemBytes{}, expErr)

		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.ErrorIs(t, err, expErr)
		assert.Equal(t, attestation.StandaloneChecker{}, checker)

		cert.AssertExpectations(t)
	})

	t.Run("cannot append root cert", func(t *testing.T) {
		cert := new(mocks.Cert)

		cert.On("PemBytes").Return(certificate.PemBytes{}, nil)

		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.ErrorContains(t, err, attestation.ErrPEMAppend)
		assert.Equal(t, attestation.StandaloneChecker{}, checker)

		cert.AssertExpectations(t)
	})
}

func TestStandaloneChecker_CheckAttestDoc(t *testing.T) {
	nonce := nitridingtest.MakeRandBytes(t, 20)
	userData := nitridingtest.MakeRandBytes(t, 512)
	publicKey := nitridingtest.MakeRandBytes(t, 1024)

	cert, err := certificate.BasePrivilegedCertBuilder{}.Build()
	require.NoError(t, err)
	require.NotNil(t, cert)

	attester, err := attestation.MakeStandaloneAttester(cert)
	assert.NoError(t, err)
	require.NotNil(t, attester)

	attestDoc, err := attester.GetAttestDoc(nonce, publicKey, userData)
	assert.NoError(t, err)
	require.NotNil(t, attestDoc)

	t.Run("happy path", func(t *testing.T) {
		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.NoError(t, err)

		attest, err := checker.CheckAttestDoc(attestDoc)
		assert.NoError(t, err)

		assert.Equal(t, nonce, attest.Document.Nonce)
		assert.Equal(t, publicKey, attest.Document.PublicKey)
		assert.Equal(t, userData, attest.Document.UserData)
	})

	t.Run("nil attestation document", func(t *testing.T) {
		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.NoError(t, err)
		require.NotEqual(t, attestation.StandaloneChecker{}, checker)

		result, err := checker.CheckAttestDoc(nil)
		assert.ErrorContains(t, err, attestation.ErrDocVerify)
		assert.Nil(t, result)
	})

	t.Run("empty attestation document", func(t *testing.T) {
		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.NoError(t, err)
		require.NotEqual(t, attestation.StandaloneChecker{}, checker)

		result, err := checker.CheckAttestDoc(attestation.CBOR{})
		assert.ErrorContains(t, err, attestation.ErrDocVerify)
		assert.Nil(t, result)
	})

	t.Run("empty roots", func(t *testing.T) {
		checker := attestation.StandaloneChecker{}
		res, err := checker.CheckAttestDoc(attestDoc)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})
}
