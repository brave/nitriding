package attestation

import (
	"errors"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

const (
	ErrNilSession = "session cannot be nil"
	ErrNSM        = "NSM device did not return an attestation"
)

type NitroAttester struct {
	session nsm.NSMSession
}

type NitroAttesterBuilder struct {
	NSMSession *nsm.Session
}

func (builder NitroAttesterBuilder) Build() (Attester, error) {
	return MakeNitroAttester(builder.NSMSession)
}

func MakeNitroAttester(session nsm.NSMSession) (NitroAttester, error) {
	if session == nil {
		return NitroAttester{}, errors.New(ErrNilSession)
	}

	return NitroAttester{
		session: session,
	}, nil
}

func (attester NitroAttester) GetAttestDoc(
	nonce,
	publicKey,
	userData []byte,
) (
	CBOR,
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
