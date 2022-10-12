package attestation

import (
	"github.com/hf/nitrite"
)

type Checker interface {
	CheckAttestDoc(attestDoc CBOR) (*nitrite.Result, error)
}
