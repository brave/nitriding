package attestation

import (
	"github.com/blocky/nitrite"
)

type Checker interface {
	Check(attestation []byte) (*nitrite.Result, error)
}
