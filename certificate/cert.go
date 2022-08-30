package certificate

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const certificateValidity = time.Hour * 24 * 356

type (
	Digest   [32]byte
	DerBytes []byte
	PemBytes []byte
)

type BasicCert interface {
	ToMemory() (PemBytes, error)
	DerBytes() DerBytes
	Digest() Digest
}

type Cert interface {
	BasicCert
	PrivateKey() (*ecdsa.PrivateKey, error)
	ToFile(fileName string) (*os.File, error)
}

func VerifyCert(t *testing.T, cert BasicCert) {
	require.NotNil(t, cert)

	pemBytes, err := cert.ToMemory()
	assert.NoError(t, err)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(pemBytes)
	assert.True(t, ok)

	intermediates := x509.NewCertPool()
	currentTime := time.Now()

	parsedCert, err := x509.ParseCertificate(cert.DerBytes())
	assert.NoError(t, err)

	_, err = parsedCert.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   currentTime,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	})
	assert.NoError(t, err)
}

func PemToDer(pemBytes PemBytes) (DerBytes, error) {
	rest := []byte{}
	var block *pem.Block
	for rest != nil {
		block, rest = pem.Decode(pemBytes)
		if block == nil {
			return DerBytes{}, errors.New("no PEM data found")
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return DerBytes{}, err
			}
			return cert.Raw, nil
		}
		pemBytes = rest
	}
	return DerBytes{}, errors.New(
		"pem.Decode failed because it didn't find a CERTIFICATE block",
	)
}

func CertDigest(derBytes DerBytes) Digest {
	return sha256.Sum256(derBytes)
}

func EncodeToMemory(derBytes DerBytes) (PemBytes, error) {
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return nil, errors.New("failed to encode certificate")
	}
	return pemCert, nil
}
