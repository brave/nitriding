package attestation

import (
	"github.com/hf/nitrite"
)

type NitroChecker struct{}

func (c NitroChecker) CheckAttestDoc(doc Doc) (*nitrite.Result, error) {
	return nitrite.Verify(doc.CBOR, nitrite.VerifyOptions{})
}
