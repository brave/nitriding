package certificate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/mdlayher/vsock"
)

const (
	ErrFQDNWhitelist    = "fqdn not in certificate manager whitelist"
	ErrListener         = "failed to create an HTTP-01 challenge listener"
	ErrGetCertFromCache = "could not get a certificate from cache"
	ErrMakeCert         = "could not make a certificate from PEM bytes"
	ErrNilListener      = "ACMECertMgr listener cannot be nil"
	ErrNilManager       = "ACMECertMgr mgr cannot be nil"
)

type CertMgr interface {
	Start() (errChan <-chan error)
	GetCert(ctx context.Context, fqdn string) (Cert, error)
	GetConfig() (*tls.Config, error)
	Close() error
}

type ACMECertMgrBuilder struct {
	CertCacheDir string
	InEnclave    bool
	Staging      bool
	Port         uint16
	FQDN         string
}

func (builder ACMECertMgrBuilder) Build() (CertMgr, error) {
	if builder.CertCacheDir == "" {
		builder.CertCacheDir = "cert-cache"
	}
	if builder.Port == 0 {
		builder.Port = 1024
	}
	certMgr, err := MakeACMECertMgr(
		builder.CertCacheDir,
		builder.InEnclave,
		builder.Staging,
		builder.Port,
		builder.FQDN,
	)
	if err != nil {
		return nil, err
	}
	return certMgr, nil
}

const (
	acmeStageEndpt = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeProdEndpt  = "https://acme-v02.api.letsencrypt.org/directory"
)

// Let's Encrypt's HTTP-01 challenge requires a listener on port 80:
// https://letsencrypt.org/docs/challenge-types/#http-01-challenge
const ACMEChallengePort = uint16(80)

type ACMECertMgr struct {
	mgr      *autocert.Manager
	listener net.Listener
}

func MakeACMECertMgr(
	certCacheDir string,
	inEnclave bool,
	staging bool,
	port uint16,
	fqdns ...string,
) (
	ACMECertMgr,
	error,
) {
	var listener net.Listener
	var err error
	if inEnclave {
		listener, err = vsock.Listen(uint32(port), nil)
	} else {
		listener, err = net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	}
	if err != nil {
		return ACMECertMgr{}, fmt.Errorf("%v: %w", ErrListener, err)
	}

	dirURL := acmeProdEndpt
	if staging {
		dirURL = acmeStageEndpt
	}
	autocertMgr := &autocert.Manager{
		Client:     &acme.Client{DirectoryURL: dirURL},
		Cache:      autocert.DirCache(certCacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(fqdns...),
	}

	return MakeACMECertMgrFromRaw(autocertMgr, listener)
}

func MakeACMECertMgrFromRaw(
	autocertMgr *autocert.Manager,
	listener net.Listener,
) (
	ACMECertMgr,
	error,
) {
	return ACMECertMgr{mgr: autocertMgr, listener: listener}, nil
}

func (certMgr ACMECertMgr) Start() <-chan error {
	errChan := make(chan error, 1)

	if certMgr.listener == nil {
		errChan <- errors.New(ErrNilListener)
		return errChan
	}
	if certMgr.mgr == nil {
		errChan <- errors.New(ErrNilManager)
		return errChan
	}

	go func() {
		errChan <- http.Serve(certMgr.listener, certMgr.mgr.HTTPHandler(nil))
		defer close(errChan)
	}()

	return errChan
}

func (certMgr ACMECertMgr) GetCert(
	ctx context.Context,
	fqdn string,
) (
	Cert,
	error,
) {
	if certMgr.mgr == nil {
		return nil, errors.New(ErrNilManager)
	}

	if err := certMgr.mgr.HostPolicy(context.Background(), fqdn); err != nil {
		return nil, fmt.Errorf("%v: %w", ErrFQDNWhitelist, err)
	}

	pemBytes, err := certMgr.mgr.Cache.Get(ctx, fqdn)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrGetCertFromCache, err)
	}

	cert, err := MakeBaseCertFromPemBytes(pemBytes, false)
	if err != nil {
		return nil, fmt.Errorf("%v:%w", ErrMakeCert, err)
	}

	return cert, nil
}

func (certMgr ACMECertMgr) GetConfig() (*tls.Config, error) {
	if certMgr.mgr == nil {
		return nil, errors.New(ErrNilManager)
	}

	return &tls.Config{GetCertificate: certMgr.mgr.GetCertificate}, nil
}

func (certMgr ACMECertMgr) Close() error {
	return certMgr.listener.Close()
}
