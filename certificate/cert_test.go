package certificate_test

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/brave/nitriding/certificate"
	"github.com/brave/nitriding/mocks"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func VerifyCert(t *testing.T, cert certificate.Cert) {
	require.NotNil(t, cert)

	pemBytes, err := cert.PemBytes()
	assert.NoError(t, err)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(pemBytes)
	assert.True(t, ok)

	intermediates := x509.NewCertPool()
	currentTime := time.Now()

	parsedCert, err := x509.ParseCertificate(cert.DerBytes())
	assert.NoError(t, err)

	_, err = parsedCert.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   currentTime,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	})
	assert.NoError(t, err)
}

func TestBaseCert_Interfaces(t *testing.T) {
	nitridingtest.AssertType[certificate.Cert](t, certificate.BaseCert{})
}

func TestMakeBaseCertFromDerBytesRaw(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		converter := new(mocks.Converter)
		derBytes := certificate.DerBytes("some DER bytes")

		cert, err := certificate.MakeBaseCertFromDerBytesRaw(derBytes, converter)
		assert.NoError(t, err)
		assert.Equal(t, cert.DerBytes(), derBytes)

		converter.AssertExpectations(t)
	})

	t.Run("nil DER bytes", func(t *testing.T) {
		converter := new(mocks.Converter)

		cert, err := certificate.MakeBaseCertFromDerBytesRaw(nil, converter)
		assert.ErrorContains(t, err, certificate.ErrNilDERBytes)
		assert.Equal(t, certificate.BaseCert{}, cert)

		converter.AssertExpectations(t)
	})
}

func TestMakeBaseCertFromPemBytesRaw(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		converter := new(mocks.Converter)
		pemBytes := certificate.PemBytes("some PEM bytes")
		derBytes := certificate.DerBytes("some DER bytes")

		converter.On("PemToDer", pemBytes).Return(derBytes, nil)

		cert, err := certificate.MakeBaseCertFromPemBytesRaw(pemBytes, converter)
		assert.NoError(t, err)
		assert.Equal(t, cert.DerBytes(), derBytes)

		converter.AssertExpectations(t)
	})

	t.Run("nil PEM bytes", func(t *testing.T) {
		converter := new(mocks.Converter)

		cert, err := certificate.MakeBaseCertFromPemBytesRaw(nil, converter)
		assert.ErrorContains(t, err, certificate.ErrNilPEMBytes)
		assert.Equal(t, certificate.BaseCert{}, cert)

		converter.AssertExpectations(t)
	})

	t.Run("PemToDer fails", func(t *testing.T) {
		converter := new(mocks.Converter)
		pemBytes := certificate.PemBytes("some PEM bytes")
		expErr := errors.New("expected error")

		converter.On("PemToDer", pemBytes).Return(nil, expErr)

		cert, err := certificate.MakeBaseCertFromPemBytesRaw(pemBytes, converter)
		assert.ErrorIs(t, err, expErr)
		assert.Equal(t, certificate.BaseCert{}, cert)

		converter.AssertExpectations(t)
	})
}

func TestBaseCert_DerBytes(t *testing.T) {
	converter := new(mocks.Converter)
	derBytes := certificate.DerBytes("some DER bytes")

	cert, err := certificate.MakeBaseCertFromDerBytesRaw(derBytes, converter)
	assert.NoError(t, err)
	assert.Equal(t, cert.DerBytes(), derBytes)

	converter.AssertExpectations(t)
}

func TestBaseCert_PemBytes(t *testing.T) {
	converter := new(mocks.Converter)
	derBytes := certificate.DerBytes("some DER bytes")
	pemBytes := certificate.PemBytes("some PEM bytes")

	converter.On("DerToPem", derBytes).Return(pemBytes, nil)

	cert, err := certificate.MakeBaseCertFromDerBytesRaw(derBytes, converter)
	assert.NoError(t, err)

	outPemBytes, err := cert.PemBytes()
	assert.NoError(t, err)
	assert.Equal(t, pemBytes, outPemBytes)

	converter.AssertExpectations(t)
}

func TestBaseCert_PemBytes_FailDerToPem(t *testing.T) {
	converter := new(mocks.Converter)
	derBytes := certificate.DerBytes("some DER bytes")
	expErr := errors.New("expected error")

	converter.On("DerToPem", derBytes).Return(nil, expErr)

	cert, err := certificate.MakeBaseCertFromDerBytesRaw(derBytes, converter)
	assert.NoError(t, err)

	outPemBytes, err := cert.PemBytes()
	assert.ErrorIs(t, err, expErr)
	assert.Nil(t, outPemBytes)

	converter.AssertExpectations(t)
}

func TestBaseCert_Digest(t *testing.T) {
	converter := new(mocks.Converter)
	derBytes := certificate.DerBytes("some DER bytes")
	digestBytes := certificate.DigestBytes(sha256.Sum256(derBytes))

	converter.On("DerToDigest", derBytes).Return(digestBytes, nil)

	cert, err := certificate.MakeBaseCertFromDerBytesRaw(derBytes, converter)
	assert.NoError(t, err)

	outDigestBytes := cert.Digest()
	assert.Equal(
		t,
		certificate.DigestBytes(sha256.Sum256(derBytes)),
		outDigestBytes,
	)

	converter.AssertExpectations(t)
}
