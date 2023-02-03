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

func TestSelfSignedAttesterBuilder_Interfaces(t *testing.T) {
	builder := attestation.SelfSignedAttesterBuilder{}
	parlor.AssertType[internal.Builder[attestation.Attester]](t, builder)
}

func TestSelfSignedAttester_Interfaces(t *testing.T) {
	attester := attestation.SelfSignedAttester{}
	parlor.AssertType[attestation.Attester](t, attester)
}

func TestSelfSignedAttesterBuilder_Build(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		attesterBuilder := attestation.SelfSignedAttesterBuilder{
			CertDERBytes:       attestation.SelfSignedAttesterCert,
			PrivateKeyDERBytes: attestation.SelfSignedAttesterPrivateKey,
		}

		attester, err := attesterBuilder.Build()
		assert.NoError(t, err)
		assert.NotNil(t, attester)
	})

	t.Run("cannot parse private key", func(t *testing.T) {
		attesterBuilder := attestation.SelfSignedAttesterBuilder{
			CertDERBytes:       attestation.SelfSignedAttesterCert,
			PrivateKeyDERBytes: nil,
		}

		attester, err := attesterBuilder.Build()
		assert.ErrorContains(t, err, attestation.ErrParsePrivateKey)
		assert.Nil(t, attester)
	})

	t.Run("cannot parse private key", func(t *testing.T) {
		attesterBuilder := attestation.SelfSignedAttesterBuilder{
			CertDERBytes:       nil,
			PrivateKeyDERBytes: attestation.SelfSignedAttesterPrivateKey,
		}

		attester, err := attesterBuilder.Build()
		assert.ErrorContains(t, err, attestation.ErrMakeCert)
		assert.Nil(t, attester)
	})
}

func TestMakeSelfSignedAttester(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		cert := certificate.BasePrivilegedCert{}

		attester, err := attestation.MakeSelfSignedAttester(cert)
		assert.NoError(t, err)
		assert.NotEqual(t, attestation.SelfSignedAttester{}, attester)
	})

	t.Run("nil cert", func(t *testing.T) {
		attester, err := attestation.MakeSelfSignedAttester(nil)
		assert.ErrorContains(t, err, attestation.ErrNilCert)
		assert.Equal(t, attestation.SelfSignedAttester{}, attester)
	})
}

func TestSelfSignedAttester_GetAttestDoc_NoMock(t *testing.T) {
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

			attester, err := attestation.MakeSelfSignedAttester(cert)
			assert.NoError(t, err)
			require.NotNil(t, attester)

			attest, err := attester.Attest(
				tc.nonce,
				tc.publicKey,
				tc.userData)
			assert.NoError(t, err)
			require.NotNil(t, attest)

			checker := attestation.SelfSignedChecker{}
			checkedAttest, err := checker.Check(attest)
			assert.NoError(t, err)

			assert.Equal(t, tc.nonce, checkedAttest.Document.Nonce)
			assert.Equal(t, tc.publicKey, checkedAttest.Document.PublicKey)
			assert.Equal(t, tc.userData, checkedAttest.Document.UserData)
		})
	}
}

type SelfSignedAttesterParlor struct {
	parlor.Parlor
	cert   *mocks.PrivilegedCert
	helper *mocks.AttesterHelper
}

func TestSelfSignedAttesterParlor(t *testing.T) {
	parlor.Run(t, new(SelfSignedAttesterParlor))
}

func (p *SelfSignedAttesterParlor) SetupSubtest() {
	p.cert = mocks.NewPrivilegedCert(p.T())
	p.helper = mocks.NewAttesterHelper(p.T())
}

func (p *SelfSignedAttesterParlor) makeAttester() attestation.SelfSignedAttester {
	return attestation.MakeSelfSignedAttesterFromRaw(p.cert, p.helper)
}

func (p *SelfSignedAttesterParlor) TestGetAttestDoc() {
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

		attest, err := attester.Attest(nonce, nil, userData)
		p.NoError(err)
		p.Equal(cosePayloadBytes, attest)
	})

	p.Run("error marshalling COSE header", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(
			coseHeaderBytes,
			expErr,
		)

		attest, err := attester.Attest(nonce, nil, userData)
		p.ErrorIs(err, expErr)
		p.Nil(attest)
	})

	p.Run("error making PCRs", func() {
		attester := attestation.MakeSelfSignedAttesterFromRaw(p.cert, p.helper)

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, expErr)

		attest, err := attester.Attest(nonce, nil, userData)
		p.ErrorIs(err, expErr)
		p.Nil(attest)
	})

	p.Run("error marshalling doc", func() {
		attester := p.makeAttester()

		p.helper.On("MarshalCBOR", coseHeader).Return(coseHeaderBytes, nil)
		p.helper.On("MakePCRs").Return(pcrs, nil)
		p.cert.On("DerBytes").Return(derBytes)
		p.helper.On("MarshalCBOR", mock.AnythingOfType("nitrite.Document")).
			Return(docBytes, expErr)

		attest, err := attester.Attest(nonce, nil, userData)
		p.ErrorIs(err, expErr)
		p.Nil(attest)
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

		attest, err := attester.Attest(nonce, nil, userData)
		p.ErrorIs(err, expErr)
		p.Nil(attest)
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

		attest, err := attester.Attest(nonce, nil, userData)
		p.ErrorIs(err, expErr)
		p.Nil(attest)
	})
}
