package attestation

import (
	"github.com/blocky/nitrite"
)

type NitroChecker struct{}

func (_ NitroChecker) Check(attestation []byte) (*nitrite.Result, error) {
	return nitrite.Verify(attestation, nitrite.VerifyOptions{})
}
