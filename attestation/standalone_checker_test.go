package attestation_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/brave/nitriding/attestation"
	"github.com/brave/nitriding/attestation/signature"
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
		cert, err := certificate.BasePrivilegedCertBuilder{}.MakePrivilegedCert()
		assert.NoError(t, err)
		require.NotNil(t, cert)

		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.NoError(t, err)
		assert.NotEqual(t, attestation.StandaloneChecker{}, checker)
	})

	t.Run("cannot get PEM bytes", func(t *testing.T) {
		cert := new(mocks.PrivilegedCert)
		expErr := errors.New("expected error")

		cert.On("PemBytes").Return(certificate.PemBytes{}, expErr)

		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.ErrorIs(t, err, expErr)
		assert.Equal(t, attestation.StandaloneChecker{}, checker)

		cert.AssertExpectations(t)
	})

	t.Run("cannot append root cert", func(t *testing.T) {
		cert := new(mocks.PrivilegedCert)

		cert.On("PemBytes").Return(certificate.PemBytes{}, nil)

		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.ErrorContains(t, err, attestation.ErrPEMAppend)
		assert.Equal(t, attestation.StandaloneChecker{}, checker)

		cert.AssertExpectations(t)
	})
}

func TestStandaloneChecker_CheckAttestDoc(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		signerPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		assert.NoError(t, err)
		require.NotNil(t, signerPrivateKey)
		signer := signature.MakePSSSigner(*signerPrivateKey)
		verifier := signature.MakePSSVerifier(signerPrivateKey.PublicKey)

		cert, err := certificate.BasePrivilegedCertBuilder{}.MakePrivilegedCert()
		assert.NoError(t, err)
		require.NotNil(t, cert)

		attester, err := attestation.MakeStandaloneAttester(signer, cert)
		assert.NoError(t, err)
		require.NotNil(t, attester)

		nonce := nitridingtest.MakeRandBytes(t, 20)
		userData := nitridingtest.MakeRandBytes(t, 20)

		attest, err := attester.GetAttestDoc(nonce, userData)
		assert.NoError(t, err)

		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.NoError(t, err)
		doc, err := checker.CheckAttestDoc(attest)
		assert.NoError(t, err)
		assert.Equal(t, nonce, doc.Document.Nonce)
		attestPublicKey, err := x509.ParsePKCS1PublicKey(doc.Document.PublicKey)
		assert.NoError(t, err)
		assert.True(t, signerPrivateKey.PublicKey.Equal(attestPublicKey))
		verifiedData, err := verifier.Verify(doc.Document.UserData)
		assert.NoError(t, err)
		assert.Equal(t, userData, verifiedData)
	})

	t.Run("nil Doc CBOR", func(t *testing.T) {
		cert, err := certificate.BasePrivilegedCertBuilder{}.MakePrivilegedCert()
		assert.NoError(t, err)
		require.NotNil(t, cert)

		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.NoError(t, err)
		require.NotEqual(t, attestation.StandaloneChecker{}, checker)

		result, err := checker.CheckAttestDoc(attestation.Doc{CBOR: nil})
		assert.ErrorContains(t, err, attestation.ErrDocVerify)
		assert.Nil(t, result)
	})

	t.Run("empty Doc CBOR", func(t *testing.T) {
		cert, err := certificate.BasePrivilegedCertBuilder{}.MakePrivilegedCert()
		assert.NoError(t, err)
		require.NotNil(t, cert)

		checker, err := attestation.MakeStandaloneChecker(cert)
		assert.NoError(t, err)
		require.NotEqual(t, attestation.StandaloneChecker{}, checker)

		result, err := checker.CheckAttestDoc(attestation.Doc{CBOR: nil})
		assert.ErrorContains(t, err, attestation.ErrDocVerify)
		assert.Nil(t, result)
	})

	t.Run("empty roots", func(t *testing.T) {
		attester, err := attestation.StandaloneAttesterBuilder{
			PrivilegedCertBuilder: certificate.BasePrivilegedCertBuilder{},
			SignerBuilder:         signature.PPSSignerBuilder{KeyLen: 1024},
		}.MakeAttester()
		assert.NoError(t, err)
		require.NotNil(t, attester)

		nonce := nitridingtest.MakeRandBytes(t, 20)
		userData := nitridingtest.MakeRandBytes(t, 20)

		attest, err := attester.GetAttestDoc(nonce, userData)
		assert.NoError(t, err)

		checker := attestation.StandaloneChecker{}
		res, err := checker.CheckAttestDoc(attest)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})
}
