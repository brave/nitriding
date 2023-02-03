package server

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/blocky/nitriding/internal/attestation"
	"github.com/blocky/nitriding/internal/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBaseServer(t *testing.T) {
	appURL := "some url"
	appPort := uint16(1234)
	tlsBundleBuilder := SelfSignedTLSBundleBuilder{
		PrivilegedCertBuilder: certificate.BasePrivilegedCertBuilder{},
	}
	tlsBundle, err := tlsBundleBuilder.Build()
	require.NoError(t, err)
	tlsConfig, err := tlsBundle.GetConfig()
	require.NoError(t, err)
	attester := attestation.SelfSignedAttester{}

	srv, err := NewBaseServer(appURL, appPort, tlsBundle, attester, true)
	assert.NoError(t, err)
	assert.Equal(t, appURL, srv.appURL)
	assert.Equal(t, appPort, srv.appPort)
	assert.Equal(t, attester, srv.attester)
	assert.Equal(t, reflect.TypeOf(tlsBundle.GetCert), reflect.TypeOf(srv.cert))
	assert.Equal(t, fmt.Sprintf(":%d", appPort), srv.httpSrv.Addr)
	assert.Equal(t, tlsConfig, srv.httpSrv.TLSConfig)
	assert.Equal(t, srv.inEnclave, srv.inEnclave)
}

func TestBaseServer_CodeURL(t *testing.T) {
	appURL := "some url"
	srv := BaseServer{appURL: appURL}

	assert.Equal(t, appURL, srv.CodeURL())
}

func TestBaseServer_InEnclave(t *testing.T) {
	srv := BaseServer{inEnclave: true}

	assert.Equal(t, srv.inEnclave, srv.InEnclave())
}
