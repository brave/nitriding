package certificate_test

import (
	"bytes"
	"encoding/pem"
	"regexp"
	"testing"

	"github.com/blocky/nitriding/certificate"
	"github.com/blocky/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPemToDer_HappyPath(t *testing.T) {
	cert, err := certificate.MakeSelfSigCert("", "")
	assert.NoError(t, err)

	pemBytes := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE",
			Bytes: cert.DerBytes()},
	)
	assert.NotNil(t, pemBytes)

	derBytes, err := certificate.PemToDer(pemBytes)
	assert.NoError(t, err)
	assert.Equal(t, cert.DerBytes(), derBytes)
}

func TestPemToDer_CannotParsePEM(t *testing.T) {
	_, err := certificate.PemToDer([]byte("not PEM data"))
	assert.ErrorContains(t, err, "no PEM data found")
}

func FuzzPemToDer_CannotParsePEM(f *testing.F) {
	f.Add([]byte("no PEM data here")) //no PEM data found
	f.Fuzz(func(t *testing.T, badPEMBytes []byte) {
		_, err := certificate.PemToDer(badPEMBytes)
		assert.ErrorContains(t, err, "no PEM data found")
	})
}

func TestEncodeToMemory_HappyPath(t *testing.T) {
	cert, err := certificate.MakeSelfSigCert("", "")
	assert.NoError(t, err)

	pemBytes, err := certificate.EncodeToMemory(cert.DerBytes())
	assert.NoError(t, err)
	assert.NotNil(t, pemBytes)

	certificate.VerifyCert(t, cert)
}

func FuzzEncodeToMemory_NeverFails(f *testing.F) {
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, derBytes []byte) {
		pemBytes, err := certificate.EncodeToMemory(derBytes)
		assert.NoError(t, err)
		assert.NotNil(t, pemBytes)
		// It is probably not possible for EncodeToMemory to fail, so if it
		// does, we should investigate
	})
}

func TestEncodeToMemoryThenPemToDer_Errors(t *testing.T) {
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
		"malformed serial number ": {
			derBytes: append([]byte{0x30, 0x30, 0x30, 0x20}, bytes.Repeat([]byte{0x30}, 46)...),
			errRegex: "x509: malformed serial number",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pemBytes, err := certificate.EncodeToMemory(tc.derBytes)
			require.NoError(t, err)
			require.NotNil(t, pemBytes)
			_, err = certificate.PemToDer(pemBytes)
			require.Error(t, err)
			assert.Regexp(t, regexp.MustCompile(tc.errRegex), err.Error())
		})
	}
}

func FuzzEncodeToMemoryThenPemToDer(f *testing.F) {
	tests := []struct {
		badDerBytes []byte
	}{
		{[]byte("asdf:")},                // x509: malformed certificate
		{bytes.Repeat([]byte{0x30}, 50)}, // x509: malformed tbs certificate
		{append([]byte{0x30, 0x30, 0x30, 0x20}, bytes.Repeat([]byte{0x30}, 46)...)}, //x509: malformed serial number
	}
	for _, tc := range tests {
		f.Add(tc.badDerBytes)
	}

	f.Fuzz(func(t *testing.T, badDerBytes []byte) {
		pemBytes, err := certificate.EncodeToMemory(badDerBytes)
		require.NoError(t, err)
		require.NotNil(t, pemBytes)
		_, pemToDerErr := certificate.PemToDer(pemBytes)

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
