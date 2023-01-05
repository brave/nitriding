package attestation_test

import (
	"errors"
	"testing"

	"github.com/blocky/nitriding/internal"
	"github.com/blocky/nitriding/internal/attestation"
	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitriding/internal/nitridingtest"
	"github.com/blocky/nitriding/mocks"
	"github.com/blocky/nitrite"
	"github.com/blocky/parlor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestStandaloneAttesterBuilder_Interfaces(t *testing.T) {
	builder := attestation.StandaloneAttesterBuilder{}
	nitridingtest.AssertType[internal.Builder[attestation.Attester]](t, builder)
}

func TestStandaloneAttester_Interfaces(t *testing.T) {
	attester := attestation.StandaloneAttester{}
	nitridingtest.AssertType[attestation.Attester](t, attester)
}

func TestStandaloneAttesterBuilder_Build(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		attesterBuilder := attestation.StandaloneAttesterBuilder{
			CertDERBytes:       attestation.StandaloneAttesterCert,
			PrivateKeyDERBytes: attestation.StandaloneAttesterPrivateKey,
		}

		attester, err := attesterBuilder.Build()
		assert.NoError(t, err)
		assert.NotNil(t, attester)
	})

	t.Run("cannot parse private key", func(t *testing.T) {
		attesterBuilder := attestation.StandaloneAttesterBuilder{
			CertDERBytes:       attestation.StandaloneAttesterCert,
			PrivateKeyDERBytes: nil,
		}

		attester, err := attesterBuilder.Build()
		assert.ErrorContains(t, err, attestation.ErrParsePrivateKey)
		assert.Nil(t, attester)
	})

	t.Run("cannot parse private key", func(t *testing.T) {
		attesterBuilder := attestation.StandaloneAttesterBuilder{
			CertDERBytes:       nil,
			PrivateKeyDERBytes: attestation.StandaloneAttesterPrivateKey,
		}

		attester, err := attesterBuilder.Build()
		assert.ErrorContains(t, err, attestation.ErrMakeCert)
		assert.Nil(t, attester)
	})
}

func TestMakeStandaloneAttester(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		cert := certificate.BasePrivilegedCert{}

		attester, err := attestation.MakeStandaloneAttester(cert)
		assert.NoError(t, err)
		assert.NotEqual(t, attestation.StandaloneAttester{}, attester)
	})

	t.Run("nil cert", func(t *testing.T) {
		attester, err := attestation.MakeStandaloneAttester(nil)
		assert.ErrorContains(t, err, attestation.ErrNilCert)
		assert.Equal(t, attestation.StandaloneAttester{}, attester)
	})
}

func TestStandaloneAttester_GetAttestDoc_NoMock(t *testing.T) {
	happyPathTests := map[string]struct {
		nonce     []byte
		userData  []byte
		publicKey []byte
	}{
		"happy path": {
			nonce:     nitridingtest.MakeRandBytes(t, 20),
			userData:  nitridingtest.MakeRandBytes(t, 512),
			publicKey: nitridingtest.MakeRandBytes(t, 1024),
		},
		"happy path - nil values": {},
	}

	for name, tc := range happyPathTests {
		t.Run(name, func(t *testing.T) {
			cert, err := certificate.BasePrivilegedCertBuilder{}.Build()
			assert.NoError(t, err)
			require.NotNil(t, cert)

			attester, err := attestation.MakeStandaloneAttester(cert)
			assert.NoError(t, err)
			require.NotNil(t, attester)

			attestDoc, err := attester.GetAttestDoc(
				tc.nonce,
				tc.publicKey,
				tc.userData)
			assert.NoError(t, err)
			require.NotNil(t, attestDoc)

			checker := attestation.StandaloneChecker{}
			attest, err := checker.CheckAttestDoc(attestDoc)
			assert.NoError(t, err)

			assert.Equal(t, tc.nonce, attest.Document.Nonce)
			assert.Equal(t, tc.publicKey, attest.Document.PublicKey)
			assert.Equal(t, tc.userData, attest.Document.UserData)
		})
	}
}

type StandaloneAttesterParlor struct {
	parlor.Parlor
	cert   *mocks.PrivilegedCert
	helper *mocks.AttesterHelper
}

func TestStandaloneAttesterParlor(t *testing.T) {
	parlor.Run(t, new(StandaloneAttesterParlor))
}

func (p *StandaloneAttesterParlor) SetupSubtest() {
	p.cert = new(mocks.PrivilegedCert)
	p.helper = new(mocks.AttesterHelper)
}

func (p *StandaloneAttesterParlor) TearDownSubtest() {
	p.cert.AssertExpectations(p.T())
	p.helper.AssertExpectations(p.T())
}

func (p *StandaloneAttesterParlor) makeAttester() attestation.StandaloneAttester {
	return attestation.MakeStandaloneAttesterFromRaw(p.cert, p.helper)
}

func (p *StandaloneAttesterParlor) TestGetAttestDoc() {
	nonce := nitridingtest.MakeRandBytes(p.T(), 20)
	userData := nitridingtest.MakeRandBytes(p.T(), 20)
	helper := attestation.BaseAttesterHelper{}

	coseHeader := nitrite.CoseHeader{Alg: attestation.COSEAlgorithm}
	coseHeaderBytes, err := helper.MarshalCBOR(coseHeader)
	p.Require().NoError(err)
	p.Require().NotNil(coseHeaderBytes)

	pcrs, err := helper.MakePCRs()
	p.Require().NoError(err)
	p.Require().NotNil(pcrs)

	cert, err := certificate.BasePrivilegedCertBuilder{}.Build()
	p.Require().NoError(err)
	p.Require().NotNil(cert)

	derBytes := cert.DerBytes()
	p.Require().NotNil(derBytes)

	docBytes := []byte("document bytes")
	privateKey := cert.PrivateKey()
	cosePayloadBytes := []byte("cose payload bytes")

	cborMsg, err := helper.MakeCOSEMessage(docBytes, privateKey)
	p.Require().NoError(err)
	p.Require().NotNil(cborMsg)

	expErr := errors.New("expected error")

	p.Run("happy path", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, nil)
		p.cert.On("DerBytes").Return(derBytes)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.Document")).
			Return(docBytes, nil)
		p.cert.On("PrivateKey").Return(privateKey)
		p.helper.On("MakeCOSEMessage", []byte(docBytes), privateKey).
			Return(cborMsg, nil)
		p.helper.On(
			"MarshalCBOR",
			mock.AnythingOfType("nitrite.CosePayload"),
		).Return(cosePayloadBytes, nil)

		attestDoc, err := attester.GetAttestDoc(nonce, nil, userData)
		p.NoError(err)
		p.Equal(cosePayloadBytes, attestDoc)
	})

	p.Run("error marshalling COSE header", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(
			coseHeaderBytes,
			expErr,
		)

		attestDoc, err := attester.GetAttestDoc(nonce, nil, userData)
		p.ErrorIs(err, expErr)
		p.Nil(attestDoc)
	})

	p.Run("error making PCRs", func() {
		attester := attestation.MakeStandaloneAttesterFromRaw(p.cert, p.helper)

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, expErr)

		attestDoc, err := attester.GetAttestDoc(nonce, nil, userData)
		p.ErrorIs(err, expErr)
		p.Nil(attestDoc)
	})

	p.Run("error marshalling doc", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, nil)
		p.cert.On("DerBytes").Return(derBytes)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.Document")).
			Return(docBytes, expErr)

		attestDoc, err := attester.GetAttestDoc(nonce, nil, userData)
		p.ErrorIs(err, expErr)
		p.Nil(attestDoc)
	})

	p.Run("error making COSE message", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, nil)
		p.cert.On("DerBytes").Return(derBytes)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.Document")).
			Return(docBytes, nil)
		p.cert.On("PrivateKey").Return(privateKey)
		p.helper.On("MakeCOSEMessage", []byte(docBytes), privateKey).
			Return(nil, expErr)

		attestDoc, err := attester.GetAttestDoc(nonce, nil, userData)
		p.ErrorIs(err, expErr)
		p.Nil(attestDoc)
	})

	p.Run("error marshalling COSE payload", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, nil)
		p.cert.On("DerBytes").Return(derBytes)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.Document")).
			Return(docBytes, nil)
		p.cert.On("PrivateKey").Return(privateKey)
		p.helper.On("MakeCOSEMessage", []byte(docBytes), privateKey).
			Return(cborMsg, nil)
		p.helper.On(
			"MarshalCBOR",
			mock.AnythingOfType("nitrite.CosePayload"),
		).
			Return(nil, expErr)

		attestDoc, err := attester.GetAttestDoc(nonce, nil, userData)
		p.ErrorIs(err, expErr)
		p.Nil(attestDoc)
	})
}
