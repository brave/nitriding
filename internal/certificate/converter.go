package certificate

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	ErrNoPEMData = "no PEM data found"
	ErrDERParse  = "could not parse out DER bytes"
	ErrPEMEncode = "could not encode DER bytes to PEM bytes"
	ErrCertParse = "could not parse Certificate"
)

type Converter interface {
	PemToDer(pemBytes PemBytes) (DerBytes, error)
	DerToPem(derBytes DerBytes) (PemBytes, error)
	DerToDigest(derBytes DerBytes) DigestBytes
}

type BaseConverter struct {
	allowCA bool
}

func MakeBaseConverter(allowCA bool) BaseConverter {
	return BaseConverter{allowCA: allowCA}
}

func (converter BaseConverter) PemToDer(pemBytes PemBytes) (DerBytes, error) {
	for len(pemBytes) > 0 {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return DerBytes{}, errors.New(ErrNoPEMData)
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return DerBytes{}, fmt.Errorf("%v: %w", ErrCertParse, err)
			}
			if !cert.IsCA || converter.allowCA {
				return cert.Raw, nil
			}
		}
		pemBytes = rest
	}

	return DerBytes{}, errors.New(ErrDERParse)
}

func (_ BaseConverter) DerToPem(derBytes DerBytes) (PemBytes, error) {
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	if pemCert == nil {
		return nil, errors.New(ErrPEMEncode)
	}
	return pemCert, nil
}

func (_ BaseConverter) DerToDigest(derBytes DerBytes) DigestBytes {
	return sha256.Sum256(derBytes)
}
