package certificate_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/blocky/nitriding/internal"
	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitriding/mocks"
	"github.com/blocky/parlor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestACMECertMgrBuilder_Interfaces(t *testing.T) {
	builder := certificate.ACMECertMgrBuilder{}
	parlor.AssertType[internal.Builder[certificate.CertMgr]](t, builder)
}

func buildCertMgr(
	t *testing.T,
	certMgrBuilder certificate.ACMECertMgrBuilder,
) certificate.CertMgr {
	certMgr, err := certMgrBuilder.Build()
	require.NoError(t, err)
	require.NotNil(t, certMgr)
	return certMgr
}

func TestACMECertMgrBuilder_Build(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		certMgr := buildCertMgr(t, certificate.ACMECertMgrBuilder{})
		defer func() { _ = certMgr.Close() }()
	})

	t.Run("singleton", func(t *testing.T) {
		certMgr := buildCertMgr(t, certificate.ACMECertMgrBuilder{})
		defer func() { _ = certMgr.Close() }()

		certMgr2, err := certificate.ACMECertMgrBuilder{}.Build()
		assert.ErrorContains(t, err, certificate.ErrListener)
		assert.ErrorContains(t, err, "bind: address already in use")
		assert.Nil(t, certMgr2)
	})

	t.Run("cannot create listener", func(t *testing.T) {
		certMgr, err := certificate.ACMECertMgrBuilder{
			InEnclave: true,
			Port:      1,
		}.Build()
		assert.ErrorContains(t, err, certificate.ErrListener)
		assert.ErrorContains(t, err, "vsock")
		assert.Nil(t, certMgr)
	})
}

func TestACMECertMgr_Interfaces(t *testing.T) {
	certMgr := certificate.ACMECertMgr{}
	parlor.AssertType[certificate.CertMgr](t, certMgr)
}

func errChanTimeout(
	t *testing.T,
	wg *sync.WaitGroup,
	errChan <-chan error,
	timeout time.Duration,
) {
	defer wg.Done()
	ctx := context.Background()
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for loop := true; loop; {
		select {
		case err := <-errChan:
			assert.NoError(t, err)
			loop = false
		case <-timeoutCtx.Done():
			assert.NotNil(t, timeoutCtx.Err())
			assert.ErrorIs(t, timeoutCtx.Err(), context.DeadlineExceeded)
			loop = false
		default:
		}
	}
}

func TestACMECertMgr_Start(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		certMgr := buildCertMgr(t, certificate.ACMECertMgrBuilder{})
		defer func() { _ = certMgr.Close() }()

		errChan := certMgr.Start()

		var wg sync.WaitGroup
		wg.Add(1)
		// assuming that 100ms is long enough for the http.Serve in Start()
		// this is a tradeoff between safety and test execution time
		go errChanTimeout(t, &wg, errChan, 100*time.Millisecond)
		wg.Wait()
	})

	t.Run("nil listener", func(t *testing.T) {
		certMgr, err := certificate.MakeACMECertMgrFromRaw(nil, nil)
		assert.NoError(t, err)

		errChan := certMgr.Start()

		assert.ErrorContains(t, <-errChan, certificate.ErrNilListener)
	})

	t.Run("nil manager", func(t *testing.T) {
		certMgr, err := certificate.MakeACMECertMgrFromRaw(
			nil,
			&net.TCPListener{},
		)
		assert.NoError(t, err)

		errChan := certMgr.Start()

		assert.ErrorContains(t, <-errChan, certificate.ErrNilManager)
	})
}

func TestACMECertMgr_GetCert(t *testing.T) {
	fqdn := "test.com"
	cert, err := certificate.MakeBasePrivilegedCert("", fqdn, false)
	require.NoError(t, err)
	require.NotNil(t, cert)
	pemBytes, err := cert.PemBytes()
	require.NoError(t, err)
	ctx := context.Background()

	t.Run("happy path", func(t *testing.T) {
		cache := new(mocks.Cache)

		cache.On("Get", mock.Anything, fqdn).Return([]byte(pemBytes), nil)

		autocertMgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      cache,
			HostPolicy: autocert.HostWhitelist([]string{fqdn}...),
		}

		certMgr, err := certificate.MakeACMECertMgrFromRaw(autocertMgr, nil)
		assert.NoError(t, err)

		cert, err := certMgr.GetCert(ctx, fqdn)
		assert.NoError(t, err)
		assert.NotNil(t, cert)

		cache.AssertExpectations(t)
	})

	t.Run("nil manager", func(t *testing.T) {
		certMgr, err := certificate.MakeACMECertMgrFromRaw(nil, nil)
		assert.NoError(t, err)

		cert, err := certMgr.GetCert(ctx, fqdn)
		assert.ErrorContains(t, err, certificate.ErrNilManager)
		assert.Nil(t, cert)

	})

	t.Run("fqdn not whitelisted", func(t *testing.T) {
		certMgr := buildCertMgr(t, certificate.ACMECertMgrBuilder{})
		defer func() { _ = certMgr.Close() }()

		cert, err := certMgr.GetCert(ctx, "not-whitelisted.com")
		assert.ErrorContains(t, err, certificate.ErrFQDNWhitelist)
		assert.Nil(t, cert)
	})

	t.Run("cache timeout", func(t *testing.T) {
		certMgr := buildCertMgr(t, certificate.ACMECertMgrBuilder{FQDN: fqdn})
		defer func() { _ = certMgr.Close() }()

		timeoutCtx, cancel := context.WithTimeout(ctx, time.Nanosecond)
		defer cancel()
		time.Sleep(2 * time.Nanosecond)

		cert, err := certMgr.GetCert(timeoutCtx, fqdn)
		assert.ErrorContains(t, err, certificate.ErrGetCertFromCache)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, cert)
	})

	t.Run("cannot make cert", func(t *testing.T) {
		cache := new(mocks.Cache)

		cache.On("Get", mock.Anything, fqdn).Return([]byte("no PEM bytes"), nil)

		autocertMgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      cache,
			HostPolicy: autocert.HostWhitelist([]string{fqdn}...),
		}

		certMgr, err := certificate.MakeACMECertMgrFromRaw(autocertMgr, nil)
		assert.NoError(t, err)

		cert, err := certMgr.GetCert(ctx, fqdn)
		assert.ErrorContains(t, err, certificate.ErrMakeCert)
		assert.ErrorContains(t, err, certificate.ErrNoPEMData)
		assert.Nil(t, cert)

		cache.AssertExpectations(t)
	})
}

func TestACMECertMgr_GetConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		certMgr := buildCertMgr(t, certificate.ACMECertMgrBuilder{})
		defer func() { _ = certMgr.Close() }()

		config, err := certMgr.GetConfig()
		assert.NoError(t, err)
		assert.NotNil(t, config)
	})

	t.Run("nil manager", func(t *testing.T) {
		certMgr, err := certificate.MakeACMECertMgrFromRaw(nil, nil)
		assert.NoError(t, err)

		config, err := certMgr.GetConfig()
		assert.ErrorContains(t, err, certificate.ErrNilManager)
		assert.Nil(t, config)
	})
}

func TestACMECertMgr_Close(t *testing.T) {
	builder := certificate.ACMECertMgrBuilder{
		InEnclave: false,
		Staging:   true,
		Port:      1024,
		FQDN:      "",
	}

	certMgr, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEqual(t, certificate.ACMECertMgr{}, certMgr)

	err = certMgr.Close()
	assert.NoError(t, err)
}
