package attestation_test

import (
	"errors"
	"testing"

	"github.com/blocky/parlor"
	"github.com/brave/nitriding/attestation"
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
	nitridingtest.AssertType[attestation.Attester](t, attester)
}

func TestNitroAttesterBuilder_Build(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		builder := attestation.NitroAttesterBuilder{NSMSession: &nsm.Session{}}

		attester, err := builder.Build()
		assert.NoError(t, err)
		assert.NotNil(t, attester)
	})
}

func TestMakeNitroAttester(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		session := nsm.Session{}

		attester, err := attestation.MakeNitroAttester(&session)
		assert.NoError(t, err)
		assert.NotEqual(t, attestation.NitroAttester{}, attester)
	})

	t.Run("nil session", func(t *testing.T) {

		attester, err := attestation.MakeNitroAttester(nil)
		assert.ErrorContains(t, err, attestation.ErrNilSession)
		assert.Equal(t, attestation.NitroAttester{}, attester)
	})
}

type NitroAttesterParlor struct {
	parlor.Parlor
	nsmSession *mocks.NSMSession
}

func TestNitroAttesterParlor(t *testing.T) {
	parlor.Run(t, new(NitroAttesterParlor))
}

func (p *NitroAttesterParlor) SetupTest() {
	p.nsmSession = new(mocks.NSMSession)
}

func (p *NitroAttesterParlor) TearDownTest() {
	p.nsmSession.AssertExpectations(p.T())
}

func (p *NitroAttesterParlor) TestGetAttestDoc() {
	nonce := []byte("nonce")
	userData := []byte("user data")
	publicKey := []byte("key bytes")
	attestDoc := attestation.CBOR("attestDoc")
	expErr := errors.New("expected error")

	p.Run("happy path", func() {
		attestReq := request.Attestation{
			Nonce:     nonce,
			UserData:  userData,
			PublicKey: publicKey,
		}
		attestRes := response.Response{
			Attestation: &response.Attestation{Document: attestDoc},
		}

		p.nsmSession.On("Send", &attestReq).Return(attestRes, nil)

		attester, err := attestation.MakeNitroAttester(p.nsmSession)
		p.NoError(err)

		outAttestDoc, err := attester.GetAttestDoc(nonce, publicKey, userData)
		p.NoError(err)
		p.Equal(attestDoc, outAttestDoc)
	}, p)

	p.Run("session.Send error", func() {
		p.nsmSession.On("Send", mock.Anything).Return(
			response.Response{},
			expErr,
		)

		attester, err := attestation.MakeNitroAttester(p.nsmSession)
		p.NoError(err)

		outAttestDoc, err := attester.GetAttestDoc(nonce, publicKey, userData)
		p.ErrorIs(err, expErr)
		p.Nil(outAttestDoc)
	}, p)

	p.Run("session.Send returns nil attestation", func() {
		p.nsmSession.On("Send", mock.Anything).Return(
			response.Response{},
			nil,
		)

		attester, err := attestation.MakeNitroAttester(p.nsmSession)
		p.NoError(err)

		outAttestDoc, err := attester.GetAttestDoc(nonce, publicKey, userData)
		p.ErrorContains(err, attestation.ErrNSM)
		p.Nil(outAttestDoc)
	}, p)

	p.Run("session.Send returns nil attestDoc", func() {
		p.nsmSession.On("Send", mock.Anything).Return(
			response.Response{
				Attestation: &response.Attestation{Document: nil},
			},
			nil,
		)

		attester, err := attestation.MakeNitroAttester(p.nsmSession)
		p.NoError(err)

		outAttestDoc, err := attester.GetAttestDoc(nonce, publicKey, userData)
		p.ErrorContains(err, attestation.ErrNSM)
		p.Nil(outAttestDoc)
	}, p)
}
