package certificate

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
			return DerBytes{}, errors.New("no PEM data found")
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return DerBytes{}, err
			}
			if !cert.IsCA || converter.allowCA {
				return cert.Raw, nil
			}
		}
		pemBytes = rest
	}

	return DerBytes{}, errors.New("could not parse out DER bytes")
}

func (_ BaseConverter) DerToPem(derBytes DerBytes) (PemBytes, error) {
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	if pemCert == nil {
		return nil, errors.New("failed to encode certificate")
	}
	return pemCert, nil
}

func (_ BaseConverter) DerToDigest(derBytes DerBytes) DigestBytes {
	return sha256.Sum256(derBytes)
}
