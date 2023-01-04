package attestation

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/blocky/nitrite"
)

const (
	ErrDocVerify = "could not verify attestation doc"
)

type StandaloneChecker struct {
}

func (_ StandaloneChecker) CheckAttestDoc(
	attestDoc []byte,
) (
	*nitrite.Result,
	error,
) {
	var roots x509.CertPool
	res, err := nitrite.Verify(
		attestDoc, nitrite.VerifyOptions{
			Roots:               &roots,
			CurrentTime:         time.Now(),
			AllowSelfSignedCert: true,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrDocVerify, err)
	}
	return res, nil
}
