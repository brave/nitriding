package certificate_test

import (
	"bytes"
	"encoding/pem"
	"regexp"
	"testing"

	"github.com/brave/nitriding/certificate"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getPemBytes(
	t *testing.T,
	derBytes certificate.DerBytes,
) certificate.PemBytes {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	assert.NotNil(t, pemBytes)
	return pemBytes
}

func makeCACert(t *testing.T) certificate.PrivilegedCert {
	cert, err := certificate.BasePrivilegedCertBuilder{}.MakePrivilegedCert()
	require.NoError(t, err)
	return cert
}

func TestBaseConverter_Interfaces(t *testing.T) {
	converter := certificate.BaseConverter{}
	nitridingtest.AttestType[certificate.Converter](t, converter)
}

func TestBaseConverter_PemToDer(t *testing.T) {
	t.Run("happy path - non CA Cert", func(t *testing.T) {
		cert, err := certificate.MakeBasePrivilegedCert("", "", false)
		require.NoError(t, err)
		require.NotNil(t, cert)

		pemBytes := getPemBytes(t, cert.DerBytes())

		derBytes, err := certificate.MakeBaseConverter(false).PemToDer(pemBytes)
		assert.NoError(t, err)
		assert.Equal(t, cert.DerBytes(), derBytes)
	})

	t.Run("happy path - CA Cert", func(t *testing.T) {
		cert := makeCACert(t)
		pemBytes := getPemBytes(t, cert.DerBytes())

		derBytes, err := certificate.MakeBaseConverter(true).PemToDer(pemBytes)
		assert.NoError(t, err)
		assert.Equal(t, cert.DerBytes(), derBytes)
	})

	t.Run("ignore CA Cert", func(t *testing.T) {
		cert := makeCACert(t)
		pemBytes := getPemBytes(t, cert.DerBytes())

		derBytes, err := certificate.MakeBaseConverter(false).PemToDer(pemBytes)
		assert.ErrorContains(t, err, certificate.ErrDERParse)
		assert.Equal(t, certificate.DerBytes{}, derBytes)
	})

	t.Run("cannot parse PEM", func(t *testing.T) {
		_, err := certificate.MakeBaseConverter(false).
			PemToDer([]byte("not PEM data"))
		assert.ErrorContains(t, err, certificate.ErrNoPEMData)
	})

	t.Run("no CERTIFICATE Block", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(
			&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{}},
		)

		derBytes, err := certificate.MakeBaseConverter(false).PemToDer(pemBytes)
		assert.ErrorContains(t, err, certificate.ErrDERParse)
		assert.Equal(t, certificate.DerBytes{}, derBytes)
	})

	t.Run("nil PEM bytes", func(t *testing.T) {
		_, err := certificate.MakeBaseConverter(false).PemToDer(nil)
		assert.ErrorContains(t, err, certificate.ErrDERParse)
	})

	tests := map[string]struct {
		pemBytes []byte
		errRegex string
	}{
		"no PEM data": {
			pemBytes: []byte("no PEM data here"),
			errRegex: certificate.ErrNoPEMData,
		},
		"nil PEM data": {
			pemBytes: nil,
			errRegex: certificate.ErrDERParse,
		},
		"empty PEM data": {
			pemBytes: []byte(""),
			errRegex: certificate.ErrDERParse,
		},
		"non CERTIFICATE PEM data": {
			pemBytes: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: []byte{},
			}),
			errRegex: certificate.ErrDERParse,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := certificate.MakeBaseConverter(false).PemToDer(tc.pemBytes)
			require.Error(t, err)
			assert.Regexp(t, regexp.MustCompile(tc.errRegex), err.Error())
		})
	}
}

func FuzzBaseConverter_PemToDer(f *testing.F) {
	tests := []struct {
		badDerBytes []byte
	}{
		{[]byte("no PEM data here")}, //no PEM data found
		{[]byte("")},                 //could not parse out DER bytes
		{nil},                        //could not parse out DER bytes
		{pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: []byte{},
		})}, //could not parse out DER bytes
	}
	for _, tc := range tests {
		f.Add(tc.badDerBytes)
	}
	f.Fuzz(func(t *testing.T, badPEMBytes []byte) {
		_, pemToDerErr := certificate.MakeBaseConverter(false).PemToDer(badPEMBytes)

		ok, err := nitridingtest.ErrorMatchesPattern(
			pemToDerErr,
			certificate.ErrNoPEMData,
			certificate.ErrDERParse,
		)
		assert.NoError(t, err)
		assert.Truef(t, ok, "pemBytes '%#v', err %v", badPEMBytes, pemToDerErr)
	})
}

func TestBaseConverter_DerToPem(t *testing.T) {
	cert := makeCACert(t)

	pemBytes, err := certificate.BaseConverter{}.DerToPem(cert.DerBytes())
	assert.NoError(t, err)
	assert.NotNil(t, pemBytes)

	VerifyCert(t, cert)
}

func FuzzBaseConverter_DerToPem(f *testing.F) {
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, derBytes []byte) {
		pemBytes, err := certificate.BaseConverter{}.DerToPem(derBytes)
		assert.NoErrorf(
			t,
			err,
			"It is probably not possible for DerToPem to fail."+
				"If it does, should investigate what happened.",
		)
		assert.NotNil(t, pemBytes)
	})
}

func TestBaseConverter_DerToPemThenPemToDer(t *testing.T) {
	tests := map[string]struct {
		derBytes []byte
		errRegex string
	}{
		"malformed certificate": {
			derBytes: []byte{},
			errRegex: "x509: malformed certificate",
		},
		"malformed tbs certificate": {
			derBytes: bytes.Repeat([]byte{0x30}, 50),
			errRegex: "x509: malformed tbs certificate",
		},
		"malformed serial number": {
			derBytes: append(
				[]byte{0x30, 0x30, 0x30, 0x20},
				bytes.Repeat([]byte{0x30}, 46)...,
			),
			errRegex: "x509: malformed serial number",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pemBytes, err := certificate.BaseConverter{}.DerToPem(tc.derBytes)
			require.NoError(t, err)
			require.NotNil(t, pemBytes)
			_, err = certificate.MakeBaseConverter(false).PemToDer(pemBytes)
			require.Error(t, err)
			assert.ErrorContains(t, err, certificate.ErrCertParse)
			assert.Regexp(t, regexp.MustCompile(tc.errRegex), err.Error())
		})
	}
}

func FuzzBaseConverter_DerToPemThenPemToDer(f *testing.F) {
	tests := []struct {
		badDerBytes []byte
	}{
		{[]byte("asdf:")},                // x509: malformed certificate
		{bytes.Repeat([]byte{0x30}, 50)}, // x509: malformed tbs certificate
		{append(
			[]byte{0x30, 0x30, 0x30, 0x20},
			bytes.Repeat([]byte{0x30}, 46)...),
		}, //x509: malformed serial number
	}
	for _, tc := range tests {
		f.Add(tc.badDerBytes)
	}

	f.Fuzz(func(t *testing.T, badDerBytes []byte) {
		pemBytes, err := certificate.BaseConverter{}.DerToPem(badDerBytes)
		require.NoError(t, err)
		require.NotNil(t, pemBytes)
		_, pemToDerErr := certificate.MakeBaseConverter(false).PemToDer(pemBytes)

		ok, err := nitridingtest.ErrorMatchesPattern(
			pemToDerErr,
			"x509: malformed certificate",
			"x509: malformed tbs certificate",
			"x509: malformed serial number",
		)
		assert.NoError(t, err)
		assert.Truef(t, ok, "derBytes '%#v', err %v", badDerBytes, pemToDerErr)
	})
}
