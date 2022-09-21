package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
)

const ErrKeyGen = "could not generate key"

type SignedData struct {
	Data []byte `json:"data"`
	Sig  []byte `json:"sig"`
}

type PSSSigner struct {
	privateKey rsa.PrivateKey
}

type PPSSignerBuilder struct {
	KeyLen int
}

func (builder PPSSignerBuilder) MakeSigner() (Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, builder.KeyLen)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrKeyGen, err)
	}

	return MakePSSSigner(*privateKey), nil
}

func MakePSSSigner(privateKey rsa.PrivateKey) PSSSigner {
	return PSSSigner{privateKey: privateKey}
}

func (s PSSSigner) Sign(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New(ErrNoDataToSign)
	}

	dataSum := sha256.Sum256(data)

	sig, err := rsa.SignPSS(
		rand.Reader,
		&s.privateKey,
		crypto.SHA256,
		dataSum[:],
		nil,
	)
	if err != nil {
		return nil, err
	}

	signedData := SignedData{Data: data, Sig: sig}
	signedDataBytes, err := json.Marshal(signedData)
	if err != nil {
		return nil, err
	}

	return signedDataBytes, nil
}

func (s PSSSigner) MarshalPublicKey() (keyBytes []byte) {
	return x509.MarshalPKCS1PublicKey(&s.privateKey.PublicKey)
}

func (s PSSSigner) ParsePublicKey(keyBytes []byte) (any, error) {
	return x509.ParsePKCS1PublicKey(keyBytes)
}
