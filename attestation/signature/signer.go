package signature

import (
	"crypto/rsa"
)

const ErrNoDataToSign = "no data to sign"

type PublicKey interface {
	*rsa.PublicKey | []byte
}

type Signer interface {
	Sign(data []byte) (signedDataBytes []byte, err error)
	MarshalPublicKey() (keyBytes []byte)
	ParsePublicKey(keyBytes []byte) (key any, err error)
}

type SignerBuilder interface {
	MakeSigner() (Signer, error)
}
