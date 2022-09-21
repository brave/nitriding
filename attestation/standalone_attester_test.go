package attestation_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/blocky/parlor"
	"github.com/brave/nitriding/attestation"
	"github.com/brave/nitriding/attestation/signature"
	"github.com/brave/nitriding/certificate"
	"github.com/brave/nitriding/mocks"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/hf/nitrite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestStandaloneAttester_Interfaces(t *testing.T) {
	attester := attestation.StandaloneAttester{}
	nitridingtest.AttestType[attestation.Attester](t, attester)
}

func TestStandaloneAttesterBuilder_MakeAttester(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		certBldr := new(mocks.PrivilegedCertBuilder)
		signerBldr := new(mocks.SignerBuilder)

		certBldr.On("MakePrivilegedCert").
			Return(certificate.BasePrivilegedCert{}, nil)
		signerBldr.On("MakeSigner").Return(signature.PSSSigner{}, nil)

		attesterBuilder := attestation.StandaloneAttesterBuilder{
			PrivilegedCertBuilder: certBldr,
			SignerBuilder:         signerBldr,
		}

		attester, err := attesterBuilder.MakeAttester()
		assert.NoError(t, err)
		assert.NotNil(t, attester)

		certBldr.AssertExpectations(t)
		signerBldr.AssertExpectations(t)
	})

	t.Run("CertBuilder error", func(t *testing.T) {
		certBldr := new(mocks.PrivilegedCertBuilder)
		signerBldr := new(mocks.SignerBuilder)
		expErr := errors.New("expected error")

		certBldr.On("MakePrivilegedCert").Return(nil, expErr)

		attesterBuilder := attestation.StandaloneAttesterBuilder{
			PrivilegedCertBuilder: certBldr,
			SignerBuilder:         signerBldr,
		}

		attester, err := attesterBuilder.MakeAttester()
		assert.ErrorIs(t, err, expErr)
		assert.Nil(t, attester)

		certBldr.AssertExpectations(t)
		signerBldr.AssertExpectations(t)
	})

	t.Run("SignerBuilder error", func(t *testing.T) {
		certBldr := new(mocks.PrivilegedCertBuilder)
		signerBldr := new(mocks.SignerBuilder)
		expErr := errors.New("expected error")

		certBldr.On("MakePrivilegedCert").Return(certificate.BasePrivilegedCert{}, nil)
		signerBldr.On("MakeSigner").Return(nil, expErr)

		attesterBuilder := attestation.StandaloneAttesterBuilder{
			PrivilegedCertBuilder: certBldr,
			SignerBuilder:         signerBldr,
		}

		attester, err := attesterBuilder.MakeAttester()
		assert.ErrorIs(t, err, expErr)
		assert.Nil(t, attester)

		certBldr.AssertExpectations(t)
		signerBldr.AssertExpectations(t)
	})
}

func TestMakeStandaloneAttester(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		signer := signature.PSSSigner{}
		cert := certificate.BasePrivilegedCert{}

		attester, err := attestation.MakeStandaloneAttester(signer, cert)
		assert.NoError(t, err)
		assert.NotEqual(t, attestation.StandaloneAttester{}, attester)
	})

	t.Run("nil signer", func(t *testing.T) {
		cert := certificate.BasePrivilegedCert{}

		attester, err := attestation.MakeStandaloneAttester(nil, cert)
		assert.ErrorContains(t, err, attestation.ErrNilSigner)
		assert.Equal(t, attestation.StandaloneAttester{}, attester)
	})

	t.Run("nil cert", func(t *testing.T) {
		signer := signature.PSSSigner{}

		attester, err := attestation.MakeStandaloneAttester(signer, nil)
		assert.ErrorContains(t, err, attestation.ErrNilCert)
		assert.Equal(t, attestation.StandaloneAttester{}, attester)
	})
}

func TestStandaloneAttester_GetAttestDoc_NoMock(t *testing.T) {
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
}

type StandaloneAttesterParlor struct {
	parlor.Parlor
	cert   *mocks.PrivilegedCert
	helper *mocks.AttesterHelper
	signer *mocks.Signer
}

func TestStandaloneAttesterParlor(t *testing.T) {
	parlor.Run(t, new(StandaloneAttesterParlor))
}

func (p *StandaloneAttesterParlor) SetupTest() {
	p.signer = new(mocks.Signer)
	p.cert = new(mocks.PrivilegedCert)
	p.helper = new(mocks.AttesterHelper)
}

func (p *StandaloneAttesterParlor) TearDownTest() {
	p.cert.AssertExpectations(p.T())
	p.helper.AssertExpectations(p.T())
	p.signer.AssertExpectations(p.T())
}

func (p *StandaloneAttesterParlor) makeAttester() attestation.StandaloneAttester {
	return attestation.MakeStandaloneAttesterFromRaw(
		p.signer,
		p.cert,
		p.helper,
	)
}

func (p *StandaloneAttesterParlor) TestGetAttestDoc() {
	nonce := nitridingtest.MakeRandBytes(p.T(), 20)
	userData := nitridingtest.MakeRandBytes(p.T(), 20)
	helper := attestation.BaseAttesterHelper{}

	coseHeader := nitrite.CoseHeader{Alg: attestation.COSEAlgorithm}
	coseHeaderBytes, err := helper.MarshalCBOR(coseHeader)
	require.NoError(p.T(), err)
	require.NotNil(p.T(), coseHeaderBytes)

	pcrs, err := helper.MakePCRs()
	require.NoError(p.T(), err)
	require.NotNil(p.T(), pcrs)

	signer, err := signature.PPSSignerBuilder{KeyLen: 1024}.MakeSigner()
	require.NoError(p.T(), err)
	require.NotNil(p.T(), signer)

	signedUserData, err := signer.Sign(userData)
	require.NoError(p.T(), err)
	require.NotNil(p.T(), signedUserData)

	cert, err := certificate.BasePrivilegedCertBuilder{}.MakePrivilegedCert()
	require.NoError(p.T(), err)
	require.NotNil(p.T(), cert)

	derBytes := cert.DerBytes()
	require.NotNil(p.T(), derBytes)

	publicKeyBytes := signer.MarshalPublicKey()
	docBytes := []byte("doc bytes")
	privateKey := cert.PrivateKey()
	codePayloadBytes := []byte("cose payload bytes")

	cborMsg, err := helper.MakeCOSEMessage(docBytes, privateKey)
	require.NoError(p.T(), err)
	require.NotNil(p.T(), cborMsg)

	expErr := errors.New("expected error")

	p.Run("happy path", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, nil)
		p.signer.On("Sign", userData).Return(signedUserData, nil)
		p.cert.On("DerBytes").Return(derBytes)
		p.signer.On("MarshalPublicKey").Return(publicKeyBytes)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.Document")).
			Return(docBytes, nil)
		p.cert.On("PrivateKey").Return(privateKey)
		p.helper.On("MakeCOSEMessage", docBytes, privateKey).
			Return(cborMsg, nil)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.CosePayload")).
			Return(codePayloadBytes, nil)

		attest, err := attester.GetAttestDoc(nonce, userData)
		assert.NoError(p.T(), err)
		require.NotNil(p.T(), attest)
		assert.Equal(p.T(), attest.CBOR, codePayloadBytes)
	}, p)

	p.Run("error marshalling COSE header", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, expErr)

		attest, err := attester.GetAttestDoc(nonce, userData)
		assert.ErrorIs(p.T(), err, expErr)
		require.NotNil(p.T(), attest)
		assert.Equal(p.T(), attestation.Doc{}, attest)
	}, p)

	p.Run("error making PCRs", func() {
		attester := attestation.MakeStandaloneAttesterFromRaw(
			p.signer,
			p.cert,
			p.helper,
		)

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, expErr)

		attest, err := attester.GetAttestDoc(nonce, userData)
		assert.ErrorIs(p.T(), err, expErr)
		require.NotNil(p.T(), attest)
		assert.Equal(p.T(), attestation.Doc{}, attest)
	}, p)

	p.Run("error signing user data", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, nil)
		p.signer.On("Sign", userData).Return(signedUserData, expErr)

		attest, err := attester.GetAttestDoc(nonce, userData)
		assert.ErrorIs(p.T(), err, expErr)
		require.NotNil(p.T(), attest)
		assert.Equal(p.T(), attestation.Doc{}, attest)
	}, p)

	p.Run("error marshalling doc", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, nil)
		p.signer.On("Sign", userData).Return(signedUserData, nil)
		p.cert.On("DerBytes").Return(derBytes)
		p.signer.On("MarshalPublicKey").Return(publicKeyBytes)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.Document")).
			Return(docBytes, expErr)

		attest, err := attester.GetAttestDoc(nonce, userData)
		assert.ErrorIs(p.T(), err, expErr)
		require.NotNil(p.T(), attest)
		assert.Equal(p.T(), attestation.Doc{}, attest)
	}, p)

	p.Run("error making COSE message", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, nil)
		p.signer.On("Sign", userData).Return(signedUserData, nil)
		p.cert.On("DerBytes").Return(derBytes)
		p.signer.On("MarshalPublicKey").Return(publicKeyBytes)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.Document")).
			Return(docBytes, nil)
		p.cert.On("PrivateKey").Return(privateKey)
		p.helper.On("MakeCOSEMessage", docBytes, privateKey).
			Return(nil, expErr)

		attest, err := attester.GetAttestDoc(nonce, userData)
		assert.ErrorIs(p.T(), err, expErr)
		require.NotNil(p.T(), attest)
		assert.Equal(p.T(), attestation.Doc{}, attest)
	}, p)

	p.Run("error marshalling COSE payload", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, nil)
		p.signer.On("Sign", userData).Return(signedUserData, nil)
		p.cert.On("DerBytes").Return(derBytes)
		p.signer.On("MarshalPublicKey").Return(publicKeyBytes)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.Document")).
			Return(docBytes, nil)
		p.cert.On("PrivateKey").Return(privateKey)
		p.helper.On("MakeCOSEMessage", docBytes, privateKey).
			Return(cborMsg, nil)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.CosePayload")).
			Return(nil, expErr)

		attest, err := attester.GetAttestDoc(nonce, userData)
		assert.ErrorIs(p.T(), err, expErr)
		require.NotNil(p.T(), attest)
		assert.Equal(p.T(), attestation.Doc{}, attest)
	}, p)
}

func TestStandaloneAttester_GetAttestCert(t *testing.T) {
	inCert, err := certificate.BasePrivilegedCertBuilder{}.MakePrivilegedCert()
	assert.NoError(t, err)
	attester, err := attestation.MakeStandaloneAttester(mocks.NewSigner(t), inCert)
	assert.NoError(t, err)
	require.NotNil(t, attester)
	outCert, err := attester.GetAttestCert()
	assert.NoError(t, err)
	assert.Equal(t, inCert.DerBytes(), outCert.DerBytes())
}
