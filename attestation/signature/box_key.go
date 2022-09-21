package signature

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

const ErrBadSliceLen = "bad slice length"

const BoxKeyLen = 32

type BoxKey [BoxKeyLen]byte
type BoxPublicKey struct {
	BoxKey
}
type BoxPrivateKey struct {
	BoxKey
}

func NewBoxKey(bytes *[BoxKeyLen]byte) *BoxKey {
	var k BoxKey
	copy(k[:], bytes[:])
	return &k
}

func NewBoxKeyFromSlice(bytes []byte) (*BoxKey, error) {
	if len(bytes) != BoxKeyLen {
		return nil,
			fmt.Errorf("%v: %d != %d", ErrBadSliceLen, len(bytes), BoxKeyLen)
	}
	var k BoxKey
	copy(k[:], bytes)
	return &k, nil
}

func (key *BoxKey) ToConstSlicePtr() *[BoxKeyLen]byte {
	var bytes [BoxKeyLen]byte = *key
	return &bytes
}

type BoxKeyPair struct {
	PublicKey  *BoxPublicKey
	PrivateKey *BoxPrivateKey
}

func MakeBoxKeyPair() (BoxKeyPair, error) {
	publicKeyBytes, privateKeyBytes, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return BoxKeyPair{}, err
	}

	publicKey := BoxPublicKey{*NewBoxKey(publicKeyBytes)}
	privateKey := BoxPrivateKey{*NewBoxKey(privateKeyBytes)}

	return BoxKeyPair{
		PublicKey:  &publicKey,
		PrivateKey: &privateKey,
	}, nil
}
