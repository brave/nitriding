package certificate

import (
	"errors"
)

const (
	ErrNilDERBytes = "DER bytes cannot be nil"
	ErrNilPEMBytes = "PEM bytes cannot be nil"
)

type (
	DigestBytes [32]byte
	DerBytes    []byte
	PemBytes    []byte
)

type Cert interface {
	DerBytes() DerBytes
	PemBytes() (PemBytes, error)
	Digest() DigestBytes
}

type BaseCert struct {
	derBytes  DerBytes
	converter Converter
}

func MakeBaseCertFromDerBytes(derBytes DerBytes) (BaseCert, error) {
	return MakeBaseCertFromDerBytesRaw(derBytes, BaseConverter{})
}

func MakeBaseCertFromDerBytesRaw(
	derBytes DerBytes,
	converter Converter,
) (
	BaseCert,
	error,
) {
	if derBytes == nil {
		return BaseCert{}, errors.New(ErrNilDERBytes)
	}

	return BaseCert{
		derBytes:  derBytes,
		converter: converter,
	}, nil
}

func MakeBaseCertFromPemBytes(
	pemBytes PemBytes,
	allowCA bool,
) (
	BaseCert,
	error,
) {
	return MakeBaseCertFromPemBytesRaw(
		pemBytes,
		BaseConverter{allowCA: allowCA},
	)
}

func MakeBaseCertFromPemBytesRaw(
	pemBytes PemBytes,
	converter Converter,
) (
	BaseCert,
	error,
) {
	if pemBytes == nil {
		return BaseCert{}, errors.New(ErrNilPEMBytes)
	}
	derBytes, err := converter.PemToDer(pemBytes)
	if err != nil {
		return BaseCert{}, err
	}
	return MakeBaseCertFromDerBytesRaw(derBytes, converter)
}

func (cert BaseCert) DerBytes() DerBytes {
	return cert.derBytes
}

func (cert BaseCert) PemBytes() (PemBytes, error) {
	return cert.converter.DerToPem(cert.derBytes)
}

func (cert BaseCert) Digest() DigestBytes {
	return cert.converter.DerToDigest(cert.derBytes)
}
