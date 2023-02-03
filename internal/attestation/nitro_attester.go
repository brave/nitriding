package attestation

import (
	"errors"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

const (
	ErrNilSession = "session cannot be nil"
	ErrNSM        = "NSM device did not return an attestation"
)

type NSMSession interface {
	Send(req request.Request) (response.Response, error)
	Read(into []byte) (int, error)
	Close() error
}

type NitroAttester struct {
	session NSMSession
}

type NitroAttesterBuilder struct {
	NSMSession *nsm.Session
}

func (builder NitroAttesterBuilder) Build() (Attester, error) {
	return MakeNitroAttester(builder.NSMSession)
}

func MakeNitroAttester(session NSMSession) (NitroAttester, error) {
	if session == nil {
		return NitroAttester{}, errors.New(ErrNilSession)
	}

	return NitroAttester{
		session: session,
	}, nil
}

func (attester NitroAttester) Attest(
	nonce,
	publicKey,
	userData []byte,
) (
	[]byte,
	error,
) {
	res, err := attester.session.Send(
		&request.Attestation{
			Nonce:     nonce,
			UserData:  userData,
			PublicKey: publicKey,
		},
	)
	if err != nil {
		return nil, err
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New(ErrNSM)
	}

	return res.Attestation.Document, nil
}
