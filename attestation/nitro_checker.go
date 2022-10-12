package attestation

import (
	"github.com/hf/nitrite"
)

type NitroChecker struct{}

func (c NitroChecker) CheckAttestDoc(attestDoc CBOR) (*nitrite.Result, error) {
	return nitrite.Verify(attestDoc, nitrite.VerifyOptions{})
}
