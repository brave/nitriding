package attestation

import (
	"github.com/blocky/nitrite"
)

type NitroChecker struct{}

func (_ NitroChecker) CheckAttestDoc(attestDoc []byte) (*nitrite.Result, error) {
	return nitrite.Verify(attestDoc, nitrite.VerifyOptions{})
}
