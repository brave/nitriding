package attestation

import (
	"github.com/blocky/nitrite"
)

type Checker interface {
	CheckAttestDoc(attestDoc []byte) (*nitrite.Result, error)
}
