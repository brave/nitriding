package attestation

import (
	"errors"

	"github.com/brave/nitriding/attestation/signature"
	"github.com/brave/nitriding/certificate"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

const (
	ErrNilSession        = "session cannot be nil"
	ErrNilSigner         = "signer cannot be nil"
	ErrNSM               = "NSM device did not return an attestation"
	ErrNoNitroAttestCert = "When " +
		"using the Nitro Enclave NSM for attestations, obtain " +
		"the attestation certificate from " +
		"https://aws-nitro-enclaves.amazonaws.com/" +
		"AWS_NitroEnclaves_Root-G1.zip. " +
		"See https://docs.aws.amazon.com/enclaves/latest/user/" +
		"verify-root.html#validation-processNitroAttester " +
		"for more information."
)

type NitroAttester struct {
	session nsm.NSMSession
	signer  signature.Signer
}

type NitroAttesterBuilder struct {
	signature.SignerBuilder
	NSMSession *nsm.Session
}

func (builder NitroAttesterBuilder) MakeAttester() (Attester, error) {
	signer, err := builder.MakeSigner()
	if err != nil {
		return nil, err
	}
	return MakeNitroAttester(builder.NSMSession, signer)
}

func MakeNitroAttester(
	session nsm.NSMSession,
	signer signature.Signer,
) (
	NitroAttester,
	error,
) {
	if session == nil {
		return NitroAttester{}, errors.New(ErrNilSession)
	}
	if signer == nil {
		return NitroAttester{}, errors.New(ErrNilSigner)
	}

	return NitroAttester{
		session: session,
		signer:  signer,
	}, nil
}

func (attester NitroAttester) GetAttestDoc(nonce, userData []byte) (CBOR, error) {
	signedUserData, err := attester.signer.Sign(userData)
	if err != nil {
		return nil, err
	}
	res, err := attester.session.Send(
		&request.Attestation{
			Nonce:     nonce,
			UserData:  signedUserData,
			PublicKey: attester.signer.MarshalPublicKey(),
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

func (attester NitroAttester) GetAttestCert() (
	certificate.PrivilegedCert,
	error,
) {
	return nil, errors.New(ErrNoNitroAttestCert)
}
