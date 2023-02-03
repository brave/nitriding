package server_test

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/blocky/nitriding/internal"
	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitriding/internal/server"
	"github.com/blocky/nitriding/mocks"
	"github.com/blocky/parlor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPrivilegedCertTLSBundle_Interfaces(t *testing.T) {
	tlsBundle := server.PrivilegedCertTLSBundle{}
	parlor.AssertType[server.TLSBundle](t, tlsBundle)
}

func TestPrivilegedCertTLSBundle_GetCert(t *testing.T) {
	cert, err := certificate.MakeBasePrivilegedCert("", "", true)
	require.NoError(t, err)
	require.NotEqual(t, certificate.BasePrivilegedCert{}, cert)

	tlsBundle := server.MakePrivilegedCertTLSBundle(cert)

	outCert, err := tlsBundle.GetCert(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, cert, outCert)
}

func TestPrivilegedCertTLSBundle_GetConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		cert := mocks.NewPrivilegedCert(t)
		// make tlsCert different from a default tls.Certificate{}
		tlsCert := tls.Certificate{OCSPStaple: []byte("some unique bytes")}

		cert.On("TLSCertificate").Return(tlsCert, nil)

		tlsBundle := server.MakePrivilegedCertTLSBundle(cert)

		config, err := tlsBundle.GetConfig()
		assert.NoError(t, err)
		require.NotNil(t, config)
		require.Positive(t, len(config.Certificates))
		assert.Equal(t, tlsCert, config.Certificates[0])
	})

	t.Run("cannot get TLSCert", func(t *testing.T) {
		cert := mocks.NewPrivilegedCert(t)
		expErr := errors.New("expected error")

		cert.On("TLSCertificate").Return(tls.Certificate{}, expErr)

		tlsBundle := server.MakePrivilegedCertTLSBundle(cert)

		config, err := tlsBundle.GetConfig()
		assert.ErrorContains(t, err, server.ErrGetTLSCert)
		assert.ErrorIs(t, err, expErr)
		assert.Nil(t, config)
	})
}

func TestCertMgrTLSBundle_Interfaces(t *testing.T) {
	tlsBundle := server.CertMgrTLSBundle{}
	parlor.AssertType[server.TLSBundle](t, &tlsBundle)
}

func TestCertMgrTLSBundle_GetCert(t *testing.T) {
	fqdn := "test.com"
	cert, err := certificate.MakeBasePrivilegedCert("", fqdn, false)
	require.NoError(t, err)
	require.NotNil(t, cert)

	t.Run("happy path - existing cert", func(t *testing.T) {
		tlsBundle := server.MakeCertMgrTLSBundleFromRaw(fqdn, nil, cert, 0)

		outCert, err := tlsBundle.GetCert(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, cert, outCert)
	})

	t.Run("happy path - new cert", func(t *testing.T) {
		certMgr := mocks.NewCertMgr(t)

		certMgr.On("GetCert", mock.Anything, fqdn).Return(cert, nil)

		tlsBundle := server.MakeCertMgrTLSBundle(fqdn, certMgr)

		cert, err := tlsBundle.GetCert(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, cert)
	})

	t.Run("cache context timeout", func(t *testing.T) {
		certMgr := mocks.NewCertMgr(t)

		certMgr.On("GetCert", mock.Anything, fqdn).
			Return(nil, errors.New(certificate.ErrGetCertFromCache)).
			Once()
		certMgr.On("GetCert", mock.Anything, fqdn).
			Return(cert, nil).
			Once()

		tlsBundle := server.MakeCertMgrTLSBundleFromRaw(
			fqdn,
			certMgr,
			nil,
			time.Millisecond,
		)

		cert, err := tlsBundle.GetCert(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, cert)
	})

	t.Run("fail get cert", func(t *testing.T) {
		certMgr := mocks.NewCertMgr(t)
		expErr := errors.New("expected error")

		certMgr.On("GetCert", mock.Anything, fqdn).Return(nil, expErr)

		tlsBundle := server.MakeCertMgrTLSBundle(fqdn, certMgr)

		cert, err := tlsBundle.GetCert(context.Background())
		assert.ErrorIs(t, err, expErr)
		assert.Nil(t, cert)
	})

	t.Run("context canceled", func(t *testing.T) {
		certMgr := mocks.NewCertMgr(t)

		certMgr.On("GetCert", mock.Anything, fqdn).
			Return(nil, errors.New(certificate.ErrGetCertFromCache)).
			Once()

		tlsBundle := server.MakeCertMgrTLSBundleFromRaw(
			fqdn,
			certMgr,
			nil,
			time.Millisecond,
		)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		cert, err := tlsBundle.GetCert(ctx)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, cert)
	})
}

func TestCertMgrTLSBundle_GetConfig(t *testing.T) {
	fqdn := "test.com"

	t.Run("happy path", func(t *testing.T) {
		certMgr := mocks.NewCertMgr(t)

		certMgr.On("GetConfig").Return(&tls.Config{}, nil)

		tlsBundle := server.MakeCertMgrTLSBundle(fqdn, certMgr)

		config, err := tlsBundle.GetConfig()
		assert.NoError(t, err)
		assert.NotNil(t, config)
	})

	t.Run("fail getting config", func(t *testing.T) {
		certMgr := mocks.NewCertMgr(t)
		expErr := errors.New("expected error")

		certMgr.On("GetConfig").Return(nil, expErr)

		tlsBundle := server.MakeCertMgrTLSBundle(fqdn, certMgr)

		config, err := tlsBundle.GetConfig()
		assert.ErrorIs(t, err, expErr)
		assert.Nil(t, config)
	})
}

func TestSelfSignedTLSBundleBuilder_Interfaces(t *testing.T) {
	builder := server.SelfSignedTLSBundleBuilder{}
	parlor.AssertType[internal.Builder[server.TLSBundle]](t, builder)
}

func TestSelfSignedTLSBundleBuilder_Build(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		certBuilder := mocks.NewBuilder[certificate.PrivilegedCert](t)
		cert, err := certificate.MakeBasePrivilegedCert("", "", false)
		require.NoError(t, err)
		require.NotEqual(t, certificate.BasePrivilegedCertBuilder{}, cert)

		certBuilder.On("Build").Return(cert, nil)

		tlsBundleBuilder := server.SelfSignedTLSBundleBuilder{
			PrivilegedCertBuilder: certBuilder,
		}

		tlsBundle, err := tlsBundleBuilder.Build()
		assert.NoError(t, err)
		require.NotNil(t, tlsBundle)

		outCert, err := tlsBundle.GetCert(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, cert, outCert)
	})

	t.Run("error making cert", func(t *testing.T) {
		certBuilder := mocks.NewBuilder[certificate.PrivilegedCert](t)
		nilCert := mocks.NewPrivilegedCert(t)
		expErr := errors.New("expected error")

		certBuilder.On("Build").Return(nilCert, expErr)

		tlsBundleBuilder := server.SelfSignedTLSBundleBuilder{
			PrivilegedCertBuilder: certBuilder,
		}

		tlsBundle, err := tlsBundleBuilder.Build()
		assert.ErrorIs(t, err, expErr)
		assert.Nil(t, tlsBundle)
	})
}

func TestCertMgrTLSBundleBuilder_Interfaces(t *testing.T) {
	builder := server.CertMgrTLSBundleBuilder{}
	parlor.AssertType[internal.Builder[server.TLSBundle]](t, &builder)
}

func TestCertMgrTLSBundleBuilder_Build(t *testing.T) {
	fqdn := "test.com"

	t.Run("happy path", func(t *testing.T) {
		certMgrBuilder := mocks.NewBuilder[certificate.CertMgr](t)
		certMgr := mocks.NewCertMgr(t)

		certMgrBuilder.On("Build").Return(certMgr, nil)
		certMgr.On("Start").Return(nil)

		tlsBundleBuilder := server.CertMgrTLSBundleBuilder{
			CertMgrBuilder: certMgrBuilder,
			FQDN:           fqdn,
		}

		tlsBundle, err := tlsBundleBuilder.Build()
		assert.NoError(t, err)
		assert.NotNil(t, tlsBundle)
	})

	t.Run("cannot make certMgr", func(t *testing.T) {
		certMgrBuilder := mocks.NewBuilder[certificate.CertMgr](t)
		nilCertMgr := mocks.NewCertMgr(t)
		expErr := errors.New("expected error")

		certMgrBuilder.On("Build").Return(nilCertMgr, expErr)

		tlsBundleBuilder := server.CertMgrTLSBundleBuilder{
			CertMgrBuilder: certMgrBuilder,
			FQDN:           fqdn,
		}

		tlsBundle, err := tlsBundleBuilder.Build()
		assert.ErrorIs(t, err, expErr)
		assert.Nil(t, tlsBundle)
	})

	t.Run("cannot start certMgr", func(t *testing.T) {
		certMgrBuilder := mocks.NewBuilder[certificate.CertMgr](t)

		certMgrBuilder.On("Build").Return(certificate.ACMECertMgr{}, nil)

		tlsBundleBuilder := server.CertMgrTLSBundleBuilder{
			CertMgrBuilder: certMgrBuilder,
			FQDN:           fqdn,
		}

		tlsBundle, err := tlsBundleBuilder.Build()
		assert.ErrorContains(t, err, server.ErrMgrStart)
		assert.Nil(t, tlsBundle)
	})
}
