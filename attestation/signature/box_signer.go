package signature

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

type BoxSigner struct {
	publicKey *BoxPublicKey
}

func MakeBoxSigner(publicKey *BoxPublicKey) BoxSigner {
	return BoxSigner{publicKey: publicKey}
}

func (s BoxSigner) Sign(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New(ErrNoDataToSign)
	}

	var out []byte
	pubKey := s.publicKey.ToConstSlicePtr()
	sig, err := box.SealAnonymous(out, data, pubKey, rand.Reader)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (s BoxSigner) MarshalPublicKey() (keyBytes []byte) {
	return s.publicKey.BoxKey[:]
}

func (s BoxSigner) ParsePublicKey(keyBytes []byte) (any, error) {
	return NewBoxKeyFromSlice(keyBytes)
}
