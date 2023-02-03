package server_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"

	"github.com/blocky/nitriding/internal"
	"github.com/blocky/nitriding/internal/attestation"
	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitriding/internal/server"
	"github.com/blocky/nitriding/mocks"
	"github.com/blocky/nitriding/pkg/nitriding"
	"github.com/blocky/parlor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaseServerBuilder_Interfaces(t *testing.T) {
	serverBuilder := server.BaseServerBuilder{}
	parlor.AssertType[internal.Builder[server.Server]](t, serverBuilder)
}

type BaseServerBuilderParlor struct {
	parlor.Parlor
	attesterBuilder  *mocks.Builder[attestation.Attester]
	tlsBundleBuilder *mocks.Builder[server.TLSBundle]
	proxyBuilder     *mocks.ProxyConfigurator
	tlsBundle        *mocks.TLSBundle
	nilTLSBundle     *mocks.TLSBundle
}

func TestBaseServerBuilderParlor(t *testing.T) {
	parlor.Run(t, new(BaseServerBuilderParlor))
}

func (p *BaseServerBuilderParlor) SetupSubtest() {
	p.attesterBuilder = mocks.NewBuilder[attestation.Attester](p.T())
	p.tlsBundleBuilder = mocks.NewBuilder[server.TLSBundle](p.T())
	p.proxyBuilder = mocks.NewProxyConfigurator(p.T())
	p.tlsBundle = mocks.NewTLSBundle(p.T())
	p.nilTLSBundle = mocks.NewTLSBundle(p.T())

}

func (p *BaseServerBuilderParlor) TestBuild() {
	tlsConfig := tls.Config{}
	expErr := errors.New("expected error")

	p.Run("happy path", func() {
		p.attesterBuilder.On("Build").
			Return(attestation.SelfSignedAttester{}, nil)
		p.tlsBundleBuilder.On("Build").
			Return(p.tlsBundle, nil)
		p.proxyBuilder.On("ConfigureSOCKSProxy").Return(nil)
		p.proxyBuilder.On("ConfigureVIProxy").Return(nil)
		p.tlsBundle.On("GetConfig").Return(&tlsConfig, nil)

		builder := server.BaseServerBuilder{
			AttesterBuilder:   p.attesterBuilder,
			TLSBundleBuilder:  p.tlsBundleBuilder,
			ProxyConfigurator: p.proxyBuilder,
		}

		srv, err := builder.Build()
		p.NoError(err)
		p.NotNil(srv)
	})

	p.Run("cannot build attester", func() {
		p.attesterBuilder.On("Build").
			Return(attestation.SelfSignedAttester{}, expErr)

		builder := server.BaseServerBuilder{
			AttesterBuilder:   p.attesterBuilder,
			TLSBundleBuilder:  p.tlsBundleBuilder,
			ProxyConfigurator: p.proxyBuilder,
		}

		srv, err := builder.Build()
		p.ErrorIs(err, expErr)
		p.Nil(srv)
	})

	p.Run("cannot build TLS bundle", func() {
		p.attesterBuilder.On("Build").
			Return(attestation.SelfSignedAttester{}, nil)
		p.tlsBundleBuilder.On("Build").
			Return(p.nilTLSBundle, expErr)

		builder := server.BaseServerBuilder{
			AttesterBuilder:   p.attesterBuilder,
			TLSBundleBuilder:  p.tlsBundleBuilder,
			ProxyConfigurator: p.proxyBuilder,
		}

		srv, err := builder.Build()
		p.ErrorIs(err, expErr)
		p.Nil(srv)
	})

	p.Run("cannot configure socks proxy", func() {
		p.attesterBuilder.On("Build").
			Return(attestation.SelfSignedAttester{}, nil)
		p.tlsBundleBuilder.On("Build").
			Return(p.tlsBundle, nil)
		p.proxyBuilder.On("ConfigureSOCKSProxy").Return(expErr)

		builder := server.BaseServerBuilder{
			AttesterBuilder:   p.attesterBuilder,
			TLSBundleBuilder:  p.tlsBundleBuilder,
			ProxyConfigurator: p.proxyBuilder,
		}

		srv, err := builder.Build()
		p.ErrorIs(err, expErr)
		p.Nil(srv)
	})

	p.Run("cannot configure viproxy", func() {
		p.attesterBuilder.On("Build").
			Return(attestation.SelfSignedAttester{}, nil)
		p.tlsBundleBuilder.On("Build").
			Return(p.tlsBundle, nil)
		p.proxyBuilder.On("ConfigureSOCKSProxy").Return(nil)
		p.proxyBuilder.On("ConfigureVIProxy").Return(expErr)

		builder := server.BaseServerBuilder{
			AttesterBuilder:   p.attesterBuilder,
			TLSBundleBuilder:  p.tlsBundleBuilder,
			ProxyConfigurator: p.proxyBuilder,
		}

		srv, err := builder.Build()
		p.ErrorIs(err, expErr)
		p.Nil(srv)
	})

	p.Run("cannot get TLS config", func() {
		p.attesterBuilder.On("Build").
			Return(attestation.SelfSignedAttester{}, nil)
		p.tlsBundleBuilder.On("Build").
			Return(p.tlsBundle, nil)
		p.proxyBuilder.On("ConfigureSOCKSProxy").Return(nil)
		p.proxyBuilder.On("ConfigureVIProxy").Return(nil)
		p.tlsBundle.On("GetConfig").Return(nil, expErr)

		builder := server.BaseServerBuilder{
			AttesterBuilder:   p.attesterBuilder,
			TLSBundleBuilder:  p.tlsBundleBuilder,
			ProxyConfigurator: p.proxyBuilder,
		}

		srv, err := builder.Build()
		p.ErrorIs(err, expErr)
		p.Nil(srv)
	})
}

func TestBaseServer_Interfaces(t *testing.T) {
	srv := server.BaseServer{}
	parlor.AssertType[server.Server](t, &srv)
}

func TestBaseServer_GetAttestDoc(t *testing.T) {
	nonce := []byte("nonce")
	publicKey := []byte("public key")
	userData := []byte("user data")
	attest := []byte("attestation")
	expErr := errors.New("expected error")

	t.Run("happy path", func(t *testing.T) {
		attester := mocks.NewAttester(t)

		attester.On("Attest", nonce, publicKey, userData).
			Return(attest, nil)

		srv := server.NewPartialBaseServerFromRaw(attester, nil)

		outAttestDoc, err := srv.Attest(nonce, publicKey, userData)
		assert.NoError(t, err)
		assert.Equal(t, attest, outAttestDoc)
	})

	t.Run("attester error", func(t *testing.T) {
		attester := mocks.NewAttester(t)

		attester.On("Attest", nonce, publicKey, userData).
			Return(nil, expErr)

		srv := server.NewPartialBaseServerFromRaw(attester, nil)

		outAttestDoc, err := srv.Attest(nonce, publicKey, userData)
		assert.Equal(t, expErr, err)
		assert.Nil(t, outAttestDoc)
	})
}

func TestBaseServer_TLSCertFingerprint(t *testing.T) {
	cert, err := certificate.BasePrivilegedCertBuilder{}.Build()
	require.NoError(t, err)
	require.NotNil(t, cert)
	expErr := errors.New("expected error")

	t.Run("happy path", func(t *testing.T) {
		getCert := func(ctx context.Context) (certificate.Cert, error) {
			return cert, nil
		}

		srv := server.NewPartialBaseServerFromRaw(nil, getCert)

		digest, err := srv.TLSCertFingerprint()
		assert.NoError(t, err)
		assert.Equal(t, cert.Digest(), digest)
	})

	t.Run("cannot get cert", func(t *testing.T) {
		getCert := func(ctx context.Context) (certificate.Cert, error) {
			return nil, expErr
		}

		srv := server.NewPartialBaseServerFromRaw(nil, getCert)

		digest, err := srv.TLSCertFingerprint()
		assert.ErrorIs(t, err, expErr)
		assert.Equal(t, certificate.DigestBytes{}, digest)
	})
}

func TestBaseServer_AddRoute(t *testing.T) {
	tlsBundleBuilder := server.SelfSignedTLSBundleBuilder{
		PrivilegedCertBuilder: certificate.BasePrivilegedCertBuilder{},
	}
	tlsBundle, err := tlsBundleBuilder.Build()
	require.NoError(t, err)

	srv, err := server.NewBaseServer(
		"some url",
		1234,
		tlsBundle,
		attestation.SelfSignedAttester{},
		true,
	)
	require.NoError(t, err)
	require.NotNil(t, srv)

	t.Run("happy path", func(t *testing.T) {
		err := srv.AddRoute(
			http.MethodGet,
			"/",
			func(writer http.ResponseWriter, request *http.Request) {
				nitriding.IndexHandler(srv, writer, request)
			},
		)
		assert.NoError(t, err)
	})

	t.Run("unknown method", func(t *testing.T) {
		err := srv.AddRoute("unknown", "/", nil)
		assert.ErrorContains(t, err, server.ErrUnknownMethod)
	})
}