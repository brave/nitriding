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

type SelfSignedChecker struct {
}

func (_ SelfSignedChecker) Check(
	attestation []byte,
) (
	*nitrite.Result,
	error,
) {
	roots := x509.NewCertPool()
	res, err := nitrite.Verify(
		attestation, nitrite.VerifyOptions{
			Roots:               roots,
			CurrentTime:         time.Now(),
			AllowSelfSignedCert: true,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrDocVerify, err)
	}
	return res, nil
}
