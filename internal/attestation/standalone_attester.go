package attestation

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitrite"
)

const (
	ErrNilCert         = "standalone attester certificate cannot be nil"
	ErrParsePrivateKey = "cannot parse private key"
	ErrMakeCert        = "could not make attester certificate"
)

// The StandaloneAttesterCert and StandaloneAttesterPrivateKey represent the
// inputs to StandaloneAttesterBuilder to build a standalone attester.
// The StandaloneAttester is intended for testing and hard-coding these values
// makes them easily available for verification of attestations in testing.
var StandaloneAttesterCert = []byte{48, 130, 1, 182, 48, 130, 1, 60, 160, 3,
	2, 1, 2, 2, 17, 0, 152, 38, 171, 126, 204, 18, 169, 6, 105, 123, 192, 41,
	56, 255, 48, 113, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 48, 11,
	49, 9, 48, 7, 6, 3, 85, 4, 10, 19, 0, 48, 30, 23, 13, 50, 50, 49, 48, 50,
	52, 49, 54, 53, 54, 52, 53, 90, 23, 13, 50, 51, 49, 48, 49, 53, 49, 54,
	53, 54, 52, 53, 90, 48, 11, 49, 9, 48, 7, 6, 3, 85, 4, 10, 19, 0, 48,
	118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34,
	3, 98, 0, 4, 61, 121, 165, 7, 236, 20, 177, 13, 95, 139, 56, 41, 15, 222,
	26, 198, 5, 151, 19, 121, 152, 63, 24, 192, 1, 255, 76, 228, 159, 35,
	115, 77, 69, 12, 188, 137, 222, 91, 26, 165, 42, 8, 150, 224, 175, 214,
	15, 106, 103, 176, 17, 135, 129, 218, 217, 238, 7, 137, 81, 52, 93, 155,
	227, 18, 244, 186, 174, 232, 222, 41, 8, 87, 250, 49, 119, 101, 195, 215,
	0, 220, 41, 80, 129, 247, 65, 204, 13, 28, 12, 212, 179, 189, 215, 112,
	140, 184, 163, 100, 48, 98, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3,
	2, 7, 128, 48, 19, 6, 3, 85, 29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5,
	7, 3, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48,
	29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 227, 102, 166, 64, 222, 237, 244, 80,
	95, 83, 165, 49, 232, 241, 218, 166, 8, 72, 219, 21, 48, 11, 6, 3, 85,
	29, 17, 4, 4, 48, 2, 130, 0, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3,
	3, 104, 0, 48, 101, 2, 49, 0, 231, 62, 27, 167, 92, 217, 44, 208, 8, 69,
	226, 151, 235, 178, 4, 135, 186, 45, 144, 51, 54, 77, 17, 221, 163, 77,
	236, 102, 113, 198, 18, 201, 226, 123, 86, 12, 123, 112, 87, 171, 250,
	90, 57, 3, 144, 158, 83, 4, 2, 48, 16, 218, 63, 82, 221, 113, 99, 184,
	19, 93, 197, 192, 117, 116, 75, 63, 82, 224, 77, 220, 194, 71, 12, 46,
	31, 85, 201, 94, 42, 44, 165, 106, 204, 57, 140, 191, 185, 207, 75, 173,
	205, 30, 5, 20, 142, 64, 49, 214}

var StandaloneAttesterPrivateKey = []byte{48, 129, 164, 2, 1, 1, 4, 48, 165,
	232, 114, 32, 183, 252, 58, 14, 147, 139, 80, 75, 69, 213, 204, 243, 112,
	102, 63, 67, 0, 126, 80, 60, 17, 139, 28, 16, 104, 45, 79, 30, 178, 230,
	195, 229, 40, 140, 224, 30, 9, 211, 128, 194, 170, 149, 243, 89, 160, 7,
	6, 5, 43, 129, 4, 0, 34, 161, 100, 3, 98, 0, 4, 61, 121, 165, 7, 236, 20,
	177, 13, 95, 139, 56, 41, 15, 222, 26, 198, 5, 151, 19, 121, 152, 63, 24,
	192, 1, 255, 76, 228, 159, 35, 115, 77, 69, 12, 188, 137, 222, 91, 26,
	165, 42, 8, 150, 224, 175, 214, 15, 106, 103, 176, 17, 135, 129, 218,
	217, 238, 7, 137, 81, 52, 93, 155, 227, 18, 244, 186, 174, 232, 222, 41,
	8, 87, 250, 49, 119, 101, 195, 215, 0, 220, 41, 80, 129, 247, 65, 204,
	13, 28, 12, 212, 179, 189, 215, 112, 140, 184}

type StandaloneAttester struct {
	cert   certificate.PrivilegedCert
	helper AttesterHelper
}

type StandaloneAttesterBuilder struct {
	CertDERBytes       []byte
	PrivateKeyDERBytes []byte
}

func (builder StandaloneAttesterBuilder) Build() (Attester, error) {
	privateKey, err := x509.ParseECPrivateKey(builder.PrivateKeyDERBytes)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrParsePrivateKey, err)
	}

	cert, err := certificate.MakeBasePrivilegedCertFromRaw(
		builder.CertDERBytes,
		certificate.BaseConverter{},
		privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrMakeCert, err)
	}

	return MakeStandaloneAttester(cert)
}

func MakeStandaloneAttester(
	cert certificate.PrivilegedCert,
) (
	StandaloneAttester,
	error,
) {
	if cert == nil {
		return StandaloneAttester{}, errors.New(ErrNilCert)
	}
	return MakeStandaloneAttesterFromRaw(cert, BaseAttesterHelper{}), nil
}

func MakeStandaloneAttesterFromRaw(
	cert certificate.PrivilegedCert,
	helper AttesterHelper,
) StandaloneAttester {
	return StandaloneAttester{cert: cert, helper: helper}
}

func (attester StandaloneAttester) GetAttestDoc(
	nonce,
	publicKey,
	userData []byte,
) (
	[]byte,
	error,
) {
	coseHeader := nitrite.CoseHeader{Alg: COSEAlgorithm}
	coseHeaderBytes, err := attester.helper.MarshalCBOR(coseHeader)
	if err != nil {
		return nil, err
	}

	pcrs, err := attester.helper.MakePCRs()
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
		PublicKey:   publicKey,
		UserData:    userData,
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
