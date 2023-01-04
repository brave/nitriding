package nitriding

import (
	"github.com/blocky/nitriding/internal/certificate"
)

func CertDigest(derBytes []byte) (certificate.DigestBytes, error) {
	cert, err := certificate.MakeBaseCertFromDerBytes(derBytes)
	if err != nil {
		return certificate.DigestBytes{}, err
	}

	return cert.Digest(), nil
}
