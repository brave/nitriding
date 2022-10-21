package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/brave/nitriding/certificate"
	"github.com/brave/nitriding/common"
)

const (
	ErrGetTLSCert = "could not get a TLS certificate"
	ErrMgrStart   = "could not start CertMgr"
)

type TLSBundle interface {
	GetCert(ctx context.Context) (certificate.Cert, error)
	GetConfig() (*tls.Config, error)
}

type PrivilegedCertTLSBundle struct {
	cert certificate.PrivilegedCert
}

func MakePrivilegedCertTLSBundle(
	cert certificate.PrivilegedCert,
) PrivilegedCertTLSBundle {
	return PrivilegedCertTLSBundle{cert: cert}
}

func (tlsBundle PrivilegedCertTLSBundle) GetCert(
	_ context.Context,
) (
	certificate.Cert,
	error,
) {
	return tlsBundle.cert, nil
}

func (tlsBundle PrivilegedCertTLSBundle) GetConfig() (*tls.Config, error) {
	tlsCert, err := tlsBundle.cert.TLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("%v:%w", ErrGetTLSCert, err)
	}

	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}, nil
}

type CertMgrTLSBundle struct {
	cert            certificate.Cert
	certMgr         certificate.CertMgr
	fqdn            string
	cacheRetryDelay time.Duration
}

func MakeCertMgrTLSBundle(
	fqdn string,
	certMgr certificate.CertMgr,
) CertMgrTLSBundle {
	return MakeCertMgrTLSBundleFromRaw(fqdn, certMgr, nil, time.Second)
}

func MakeCertMgrTLSBundleFromRaw(fqdn string, certMgr certificate.CertMgr, cert certificate.Cert, cacheRetryDelay time.Duration) CertMgrTLSBundle {
	return CertMgrTLSBundle{
		cert:            cert,
		certMgr:         certMgr,
		fqdn:            fqdn,
		cacheRetryDelay: cacheRetryDelay,
	}
}

func (tlsBundle *CertMgrTLSBundle) getCachedCert(
	timeout time.Duration,
) (
	certificate.Cert,
	error,
) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return tlsBundle.certMgr.GetCert(ctx, tlsBundle.fqdn)
}

func (tlsBundle *CertMgrTLSBundle) GetCert(
	ctx context.Context,
) (
	certificate.Cert,
	error,
) {
	var err error
	if tlsBundle.cert == nil {
		for {
			tlsBundle.cert, err = tlsBundle.getCachedCert(time.Minute)
			if err != nil &&
				strings.Contains(err.Error(), certificate.ErrGetCertFromCache) {
				time.Sleep(tlsBundle.cacheRetryDelay)
			} else if err != nil {
				return nil, fmt.Errorf("%v:%w", ErrGetTLSCert, err)
			} else {
				break
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				continue
			}
		}
	}
	return tlsBundle.cert, nil
}

func (tlsBundle *CertMgrTLSBundle) GetConfig() (*tls.Config, error) {
	return tlsBundle.certMgr.GetConfig()
}

type SelfSignedTLSBundleBuilder struct {
	PrivilegedCertBuilder common.Builder[certificate.PrivilegedCert]
}

func (builder SelfSignedTLSBundleBuilder) Build() (TLSBundle, error) {
	cert, err := builder.PrivilegedCertBuilder.Build()
	if err != nil {
		return nil, err
	}

	return MakePrivilegedCertTLSBundle(cert), nil
}

type CertMgrTLSBundleBuilder struct {
	CertMgrBuilder common.Builder[certificate.CertMgr]
	FQDN           string
}

func (builder *CertMgrTLSBundleBuilder) Build() (TLSBundle, error) {
	certMgr, err := builder.CertMgrBuilder.Build()
	if err != nil {
		return nil, err
	}

	errChan := certMgr.Start()

	// wait some time for the certMgr to start serving to see if it errors
	err = errChanOrTimeout(errChan, 100*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("%v: %w", ErrMgrStart, err)
	}

	certMgrTLSBundle := MakeCertMgrTLSBundle(builder.FQDN, certMgr)
	return &certMgrTLSBundle, nil
}

func errChanOrTimeout(errChan <-chan error, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return ctx.Err()
		default:
			continue
		}
	}
}
