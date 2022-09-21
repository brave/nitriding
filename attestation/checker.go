package attestation

import (
	"github.com/hf/nitrite"
)

type Checker interface {
	CheckAttestDoc(attestDoc Doc) (*nitrite.Result, error)
}
