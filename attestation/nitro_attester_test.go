package attestation_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/blocky/parlor"
	"github.com/brave/nitriding/attestation"
	"github.com/brave/nitriding/attestation/signature"
	"github.com/brave/nitriding/mocks"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNitroAttester_Interfaces(t *testing.T) {
	attester := attestation.NitroAttester{}
	nitridingtest.AttestType[attestation.Attester](t, attester)
}

func TestNitroAttesterBuilder_MakeAttester(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		signerBldr := new(mocks.SignerBuilder)

		signerBldr.On("MakeSigner").Return(signature.PSSSigner{}, nil)

		builder := attestation.NitroAttesterBuilder{
			SignerBuilder: signerBldr,
			NSMSession:    &nsm.Session{},
		}

		attester, err := builder.MakeAttester()
		assert.NoError(t, err)
		assert.NotNil(t, attester)

		signerBldr.AssertExpectations(t)
	})

	t.Run("signer builder error", func(t *testing.T) {
		signerBldr := new(mocks.SignerBuilder)
		expErr := errors.New("expected error")

		signerBldr.On("MakeSigner").Return(nil, expErr)

		builder := attestation.NitroAttesterBuilder{
			SignerBuilder: signerBldr,
			NSMSession:    &nsm.Session{},
		}

		attester, err := builder.MakeAttester()
		assert.ErrorIs(t, err, expErr)
		assert.Nil(t, attester)

		signerBldr.AssertExpectations(t)
	})
}

func TestMakeNitroAttester(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		session := nsm.Session{}
		signer := signature.PSSSigner{}

		attester, err := attestation.MakeNitroAttester(&session, signer)
		assert.NoError(t, err)
		assert.NotEqual(t, attestation.NitroAttester{}, attester)
	})

	t.Run("nil session", func(t *testing.T) {
		signer := signature.PSSSigner{}

		attester, err := attestation.MakeNitroAttester(nil, signer)
		assert.ErrorContains(t, err, attestation.ErrNilSession)
		assert.Equal(t, attestation.NitroAttester{}, attester)
	})

	t.Run("nil signer", func(t *testing.T) {
		session := nsm.Session{}

		attester, err := attestation.MakeNitroAttester(&session, nil)
		assert.ErrorContains(t, err, attestation.ErrNilSigner)
		assert.Equal(t, attestation.NitroAttester{}, attester)
	})
}

type NitroAttesterParlor struct {
	parlor.Parlor
	attestDoc           attestation.CBOR
	expErr              error
	keyBytes            []byte
	nonce               []byte
	nsmSession          *mocks.NSMSession
	signer              *mocks.Signer
	signedUserDataBytes []byte
	userData            []byte
}

func TestNitroAttesterParlor(t *testing.T) {
	parlor.Run(t, new(NitroAttesterParlor))
}

func (p *NitroAttesterParlor) SetupTest() {
	var err error
	p.nsmSession = new(mocks.NSMSession)
	p.signer = new(mocks.Signer)

	p.nonce = []byte("nonce")
	p.userData = []byte("user data")
	signedUserData := signature.SignedData{
		Data: p.userData,
		Sig:  nil,
	}
	p.signedUserDataBytes, err = json.Marshal(signedUserData)
	p.Require().NoError(err)
	p.keyBytes = []byte("key bytes")
	p.attestDoc = attestation.CBOR("attestDoc")
	p.expErr = errors.New("expected error")
}

func (p *NitroAttesterParlor) TearDownTest() {
	p.nsmSession.AssertExpectations(p.T())
	p.signer.AssertExpectations(p.T())
}

func (p *NitroAttesterParlor) TestGetAttestDoc() {
	p.Run("happy path", func() {
		attestReq := request.Attestation{
			Nonce:     p.nonce,
			UserData:  p.signedUserDataBytes,
			PublicKey: p.keyBytes,
		}
		attestRes := response.Response{
			Attestation: &response.Attestation{Document: p.attestDoc},
		}

		p.signer.On("Sign", p.userData).Return(p.signedUserDataBytes, nil)
		p.signer.On("MarshalPublicKey").Return(p.keyBytes)
		p.nsmSession.On("Send", &attestReq).Return(attestRes, nil)

		attester, err := attestation.MakeNitroAttester(
			p.nsmSession,
			p.signer,
		)
		p.NoError(err)

		attestDoc, err := attester.GetAttestDoc(p.nonce, p.userData)
		p.NoError(err)
		p.Equal(p.attestDoc, attestDoc)
	}, p)

	p.Run("signer.Sign error", func() {
		p.signer.On("Sign", p.userData).Return(nil, p.expErr)

		attester, err := attestation.MakeNitroAttester(
			p.nsmSession,
			p.signer,
		)
		p.NoError(err)

		attestDoc, err := attester.GetAttestDoc(p.nonce, p.userData)
		p.ErrorIs(err, p.expErr)
		p.Nil(attestDoc)
	}, p)

	p.Run("session.Send error", func() {
		p.signer.On("Sign", p.userData).Return(p.signedUserDataBytes, nil)
		p.signer.On("MarshalPublicKey").Return(p.keyBytes)
		p.nsmSession.On("Send", mock.Anything).Return(
			response.Response{},
			p.expErr,
		)

		attester, err := attestation.MakeNitroAttester(
			p.nsmSession,
			p.signer,
		)
		p.NoError(err)

		attestDoc, err := attester.GetAttestDoc(p.nonce, p.userData)
		p.ErrorIs(err, p.expErr)
		p.Nil(attestDoc)
	}, p)

	p.Run("session.Send returns nil attestation", func() {
		p.signer.On("Sign", p.userData).Return(p.signedUserDataBytes, nil)
		p.signer.On("MarshalPublicKey").Return(p.keyBytes)
		p.nsmSession.On("Send", mock.Anything).Return(
			response.Response{},
			nil,
		)

		attester, err := attestation.MakeNitroAttester(
			p.nsmSession,
			p.signer,
		)
		p.NoError(err)

		attestDoc, err := attester.GetAttestDoc(p.nonce, p.userData)
		p.ErrorContains(err, attestation.ErrNSM)
		p.Nil(attestDoc)
	}, p)

	p.Run("session.Send returns nil attestDoc", func() {
		p.signer.On("Sign", p.userData).Return(p.signedUserDataBytes, nil)
		p.signer.On("MarshalPublicKey").Return(p.keyBytes)
		p.nsmSession.On("Send", mock.Anything).Return(
			response.Response{
				Attestation: &response.Attestation{Document: nil},
			},
			nil,
		)

		attester, err := attestation.MakeNitroAttester(
			p.nsmSession,
			p.signer,
		)
		p.NoError(err)

		attestDoc, err := attester.GetAttestDoc(p.nonce, p.userData)
		p.ErrorContains(err, attestation.ErrNSM)
		p.Nil(attestDoc)
	}, p)

}

func TestNitroAttester_GetAttestCert(t *testing.T) {
	attester := attestation.NitroAttester{}
	cert, err := attester.GetAttestCert()
	assert.Nil(t, cert)
	assert.ErrorContains(t, err, attestation.ErrNoNitroAttestCert)
}
