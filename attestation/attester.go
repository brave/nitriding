package attestation

import (
	"github.com/brave/nitriding/certificate"
	"github.com/veraison/go-cose"
)

const COSEAlgorithm = cose.AlgorithmES384

type Attester interface {
	GetAttestDoc(nonce, userData []byte) (attestDoc Doc, err error)
	GetAttestCert() (cert certificate.PrivilegedCert, err error)
}

type AttesterBuilder interface {
	MakeAttester() (Attester, error)
}
