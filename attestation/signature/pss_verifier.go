package signature

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

const (
	ErrUnmarshalling = "failed to unmarshal signed data"
	ErrVerifying     = "failed to verify RSA signature"
)

type PSSVerifier struct {
	publicKey rsa.PublicKey
}

func MakePSSVerifier(publicKey rsa.PublicKey) PSSVerifier {
	return PSSVerifier{publicKey: publicKey}
}

func (v PSSVerifier) Verify(signedDataBytes []byte) ([]byte, error) {
	var signedData SignedData
	err := json.Unmarshal(signedDataBytes, &signedData)
	if err != nil {
		return nil,
			fmt.Errorf("%v: %v: %w", ErrBadSignature, ErrUnmarshalling, err)
	}

	dataSum := sha256.Sum256(signedData.Data)

	err = rsa.VerifyPSS(
		&v.publicKey,
		crypto.SHA256,
		dataSum[:],
		signedData.Sig,
		nil,
	)
	if err != nil {
		return nil,
			fmt.Errorf("%v: %v: %w", ErrBadSignature, ErrVerifying, err)
	}

	return signedData.Data, nil
}
