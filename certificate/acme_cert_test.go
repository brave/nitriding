package certificate_test

import (
	"errors"
	"testing"

	"github.com/blocky/nitriding/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeACMECert_HappyPath(t *testing.T) {
	selfSigCert, err := certificate.MakeSelfSigCert("", "")
	require.NoError(t, err)
	certificate.VerifyCert(t, selfSigCert)

	acmeCert := certificate.MakeACMECert(selfSigCert.DerBytes())
	assert.NoError(t, err)
	assert.NotNil(t, acmeCert)
	assert.Equal(t, selfSigCert.Digest(), acmeCert.Digest())

	pemBytes, err := acmeCert.ToMemory()
	assert.NoError(t, err)
	assert.NotNil(t, pemBytes)

	certificate.VerifyCert(t, acmeCert)
}

func TestACMECert_ToMemory_CannotEncode(t *testing.T) {
	expErr := errors.New("expected error")
	encodeToMemory := func(
		derBytes certificate.DerBytes,
	) (
		certificate.PemBytes,
		error,
	) {
		return nil, expErr
	}

	var digest certificate.Digest
	cert := certificate.MakeACMECertFromRaw(nil, digest, encodeToMemory)
	pemBytes, err := cert.ToMemory()
	assert.ErrorIs(t, err, expErr)
	assert.Nil(t, pemBytes)
}

func TestACMECert_DerBytes_HappyPath(t *testing.T) {
	derBytes := certificate.DerBytes("test bytes")
	cert := certificate.MakeACMECert(derBytes)
	assert.Equal(t, derBytes, cert.DerBytes())
}

func TestACMECert_Digest_HappyPath(t *testing.T) {
	derBytes := certificate.DerBytes("test bytes")
	cert := certificate.MakeACMECert(derBytes)
	assert.Equal(t, certificate.CertDigest(derBytes), cert.Digest())
}
