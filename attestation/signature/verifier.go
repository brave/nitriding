package signature

const ErrBadSignature = "failed to verify signature"

type Verifier interface {
	Verify(signedDataBytes []byte) (data []byte, err error)
}
