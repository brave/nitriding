package signature

import (
	"errors"

	"golang.org/x/crypto/nacl/box"
)

type BoxVerifier struct {
	key BoxKeyPair
}

func MakeBoxVerifier(key BoxKeyPair) BoxVerifier {
	return BoxVerifier{key: key}
}

func (v BoxVerifier) Verify(signedDataBytes []byte) ([]byte, error) {
	decrypted, ok := box.OpenAnonymous(
		nil,
		signedDataBytes,
		v.key.PublicKey.ToConstSlicePtr(),
		v.key.PrivateKey.ToConstSlicePtr(),
	)
	if !ok {
		return nil, errors.New(ErrBadSignature)
	}
	return decrypted, nil
}
