package attestation

import (
	"github.com/veraison/go-cose"
)

const COSEAlgorithm = cose.AlgorithmES384

type Attester interface {
	GetAttestDoc(nonce, publicKey, userData []byte) (attestDoc []byte, err error)
}
