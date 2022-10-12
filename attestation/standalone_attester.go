package attestation

import (
	"errors"
	"time"

	"github.com/brave/nitriding/attestation/signature"
	"github.com/brave/nitriding/certificate"
	"github.com/hf/nitrite"
)

const ErrNilCert = "cert cannot be nil"

type StandaloneAttester struct {
	signer signature.Signer
	cert   certificate.PrivilegedCert
	helper AttesterHelper
}

type StandaloneAttesterBuilder struct {
	certificate.PrivilegedCertBuilder
	signature.SignerBuilder
}

func (builder StandaloneAttesterBuilder) MakeAttester() (Attester, error) {
	cert, err := builder.MakePrivilegedCert()
	if err != nil {
		return nil, err
	}

	signer, err := builder.MakeSigner()
	if err != nil {
		return nil, err
	}

	return MakeStandaloneAttester(signer, cert)
}

func MakeStandaloneAttester(
	signer signature.Signer,
	cert certificate.PrivilegedCert,
) (
	StandaloneAttester,
	error,
) {
	if signer == nil {
		return StandaloneAttester{}, errors.New(ErrNilSigner)
	}
	if cert == nil {
		return StandaloneAttester{}, errors.New(ErrNilCert)
	}

	return MakeStandaloneAttesterFromRaw(
		signer,
		cert,
		BaseAttesterHelper{},
	), nil
}

func MakeStandaloneAttesterFromRaw(
	signer signature.Signer,
	cert certificate.PrivilegedCert,
	helper AttesterHelper,
) StandaloneAttester {
	return StandaloneAttester{signer: signer, cert: cert, helper: helper}
}

func (attester StandaloneAttester) GetAttestDoc(nonce, userData []byte) (CBOR, error) {
	coseHeader := nitrite.CoseHeader{Alg: COSEAlgorithm}
	coseHeaderBytes, err := attester.helper.MarshalCBOR(coseHeader)
	if err != nil {
		return nil, err
	}

	pcrs, err := attester.helper.MakePCRs()
	if err != nil {
		return nil, err
	}

	signedUserData, err := attester.signer.Sign(userData)
	if err != nil {
		return nil, err
	}

	doc := nitrite.Document{
		ModuleID:    "i-0e811925634bbd863-enc018274a97f16d616", // example value
		Timestamp:   uint64(time.Now().Unix()),
		Digest:      "SHA384",
		PCRs:        pcrs,
		Certificate: attester.cert.DerBytes(),
		CABundle:    nil,
		PublicKey:   attester.signer.MarshalPublicKey(),
		UserData:    signedUserData,
		Nonce:       nonce,
	}
	docBytes, err := attester.helper.MarshalCBOR(doc)
	if err != nil {
		return nil, err
	}

	privateKey := attester.cert.PrivateKey()
	coseMsg, err := attester.helper.MakeCOSEMessage(docBytes, privateKey)
	if err != nil {
		return nil, err
	}

	cosePayload := nitrite.CosePayload{
		Protected:   coseHeaderBytes,
		Unprotected: nil,
		Payload:     docBytes,
		Signature:   coseMsg.Signature,
	}

	cosePayloadBytes, err := attester.helper.MarshalCBOR(cosePayload)
	if err != nil {
		return nil, err
	}

	return cosePayloadBytes, nil
}

func (attester StandaloneAttester) GetAttestCert() (
	certificate.PrivilegedCert,
	error,
) {
	return attester.cert, nil
}
