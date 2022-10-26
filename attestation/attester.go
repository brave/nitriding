package attestation

import (
	"github.com/veraison/go-cose"
)

const COSEAlgorithm = cose.AlgorithmES384

type CBOR []byte

type Attester interface {
	GetAttestDoc(nonce, publicKey, userData []byte) (attestDoc CBOR, err error)
}
