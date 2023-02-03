package attestation

import (
	"github.com/veraison/go-cose"
)

const COSEAlgorithm = cose.AlgorithmES384

type Attester interface {
	Attest(nonce, publicKey, userData []byte) (attestation []byte, err error)
}
