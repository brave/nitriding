package attestation

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/brave/nitriding/certificate"
	"github.com/hf/nitrite"
)

const (
	ErrPEMAppend = "could not append root certificate from PEM bytes"
	ErrDocVerify = "could not verify attestation doc"
)

type StandaloneChecker struct {
	roots *x509.CertPool
}

func MakeStandaloneChecker(cert certificate.Cert) (StandaloneChecker, error) {
	pemBytes, err := cert.PemBytes()
	if err != nil {
		return StandaloneChecker{}, err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(pemBytes)
	if !ok {
		return StandaloneChecker{}, fmt.Errorf(ErrPEMAppend)
	}

	return StandaloneChecker{roots: roots}, nil
}

func (c StandaloneChecker) CheckAttestDoc(doc Doc) (*nitrite.Result, error) {
	res, err := nitrite.Verify(doc.CBOR, nitrite.VerifyOptions{
		Roots:               c.roots,
		CurrentTime:         time.Now(),
		AllowSelfSignedCert: true,
	})
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrDocVerify, err)
	}
	return res, nil
}
