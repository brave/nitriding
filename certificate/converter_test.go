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

var nonCADerBytes = certificate.DerBytes{48, 130, 4, 87, 48, 130, 3, 63, 160, 3, 2, 1, 2, 2, 18, 4, 238, 229, 253, 55, 94, 148, 213, 154, 145, 224, 128, 231, 147, 53, 165, 57, 217, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 50, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 22, 48, 20, 6, 3, 85, 4, 10, 19, 13, 76, 101, 116, 39, 115, 32, 69, 110, 99, 114, 121, 112, 116, 49, 11, 48, 9, 6, 3, 85, 4, 3, 19, 2, 82, 51, 48, 30, 23, 13, 50, 50, 48, 56, 50, 57, 49, 57, 53, 57, 50, 57, 90, 23, 13, 50, 50, 49, 49, 50, 55, 49, 57, 53, 57, 50, 56, 90, 48, 25, 49, 23, 48, 21, 6, 3, 85, 4, 3, 19, 14, 109, 119, 105, 116, 116, 105, 101, 46, 98, 107, 121, 46, 115, 104, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 220, 38, 9, 45, 214, 163, 139, 174, 53, 201, 240, 30, 71, 242, 168, 209, 84, 179, 49, 117, 110, 154, 41, 108, 176, 163, 183, 54, 184, 86, 108, 167, 226, 25, 44, 42, 33, 3, 124, 193, 194, 87, 19, 196, 152, 241, 163, 66, 250, 198, 140, 224, 183, 132, 85, 230, 2, 75, 12, 207, 236, 236, 90, 160, 163, 130, 2, 73, 48, 130, 2, 69, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 29, 6, 3, 85, 29, 37, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 176, 219, 234, 34, 66, 65, 63, 241, 246, 79, 105, 178, 12, 35, 11, 133, 16, 194, 114, 92, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 20, 46, 179, 23, 183, 88, 86, 203, 174, 80, 9, 64, 230, 31, 175, 157, 139, 20, 194, 198, 48, 85, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 73, 48, 71, 48, 33, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 21, 104, 116, 116, 112, 58, 47, 47, 114, 51, 46, 111, 46, 108, 101, 110, 99, 114, 46, 111, 114, 103, 48, 34, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 22, 104, 116, 116, 112, 58, 47, 47, 114, 51, 46, 105, 46, 108, 101, 110, 99, 114, 46, 111, 114, 103, 47, 48, 25, 6, 3, 85, 29, 17, 4, 18, 48, 16, 130, 14, 109, 119, 105, 116, 116, 105, 101, 46, 98, 107, 121, 46, 115, 104, 48, 76, 6, 3, 85, 29, 32, 4, 69, 48, 67, 48, 8, 6, 6, 103, 129, 12, 1, 2, 1, 48, 55, 6, 11, 43, 6, 1, 4, 1, 130, 223, 19, 1, 1, 1, 48, 40, 48, 38, 6, 8, 43, 6, 1, 5, 5, 7, 2, 1, 22, 26, 104, 116, 116, 112, 58, 47, 47, 99, 112, 115, 46, 108, 101, 116, 115, 101, 110, 99, 114, 121, 112, 116, 46, 111, 114, 103, 48, 130, 1, 4, 6, 10, 43, 6, 1, 4, 1, 214, 121, 2, 4, 2, 4, 129, 245, 4, 129, 242, 0, 240, 0, 118, 0, 111, 83, 118, 172, 49, 240, 49, 25, 216, 153, 0, 164, 81, 21, 255, 119, 21, 28, 17, 217, 2, 193, 0, 41, 6, 141, 178, 8, 154, 55, 217, 19, 0, 0, 1, 130, 235, 102, 244, 129, 0, 0, 4, 3, 0, 71, 48, 69, 2, 32, 9, 208, 84, 247, 31, 214, 144, 171, 40, 200, 47, 54, 146, 45, 196, 144, 96, 137, 26, 197, 218, 170, 56, 197, 36, 29, 26, 129, 156, 40, 83, 48, 2, 33, 0, 187, 247, 142, 161, 87, 6, 21, 33, 166, 193, 184, 242, 230, 15, 175, 171, 179, 55, 192, 189, 74, 62, 72, 231, 181, 22, 13, 207, 39, 215, 67, 137, 0, 118, 0, 70, 165, 85, 235, 117, 250, 145, 32, 48, 181, 162, 137, 105, 244, 243, 125, 17, 44, 65, 116, 190, 253, 73, 184, 133, 171, 242, 252, 112, 254, 109, 71, 0, 0, 1, 130, 235, 102, 244, 110, 0, 0, 4, 3, 0, 71, 48, 69, 2, 33, 0, 175, 180, 75, 177, 36, 33, 67, 242, 214, 128, 115, 184, 97, 202, 224, 66, 185, 14, 156, 72, 179, 36, 143, 155, 51, 110, 48, 149, 119, 63, 7, 252, 2, 32, 72, 195, 184, 151, 249, 110, 117, 127, 85, 113, 198, 6, 24, 131, 63, 171, 216, 255, 74, 254, 187, 132, 94, 15, 19, 57, 14, 163, 108, 133, 173, 107, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 169, 235, 164, 51, 122, 147, 236, 62, 5, 173, 106, 246, 98, 97, 49, 32, 206, 67, 47, 70, 55, 128, 227, 118, 187, 151, 171, 15, 63, 47, 31, 68, 252, 59, 160, 33, 250, 223, 26, 34, 139, 203, 199, 100, 95, 124, 180, 21, 47, 181, 166, 226, 32, 212, 17, 152, 217, 183, 78, 3, 46, 26, 251, 201, 176, 125, 16, 36, 231, 112, 8, 187, 79, 56, 216, 144, 123, 192, 56, 80, 188, 58, 23, 89, 118, 243, 137, 193, 154, 180, 60, 71, 7, 58, 29, 195, 104, 86, 182, 111, 163, 220, 43, 233, 227, 160, 120, 25, 59, 57, 64, 111, 144, 6, 118, 219, 198, 125, 217, 77, 64, 194, 201, 216, 65, 165, 55, 91, 143, 244, 133, 244, 82, 57, 64, 180, 212, 215, 183, 232, 156, 232, 191, 18, 33, 36, 239, 14, 249, 195, 2, 226, 130, 98, 164, 38, 85, 242, 138, 144, 55, 199, 138, 121, 159, 63, 243, 45, 26, 122, 80, 250, 203, 154, 96, 69, 131, 67, 71, 42, 10, 178, 39, 187, 249, 15, 244, 250, 123, 130, 69, 155, 222, 51, 213, 77, 180, 136, 14, 179, 21, 76, 152, 135, 28, 190, 36, 214, 208, 28, 141, 243, 42, 195, 186, 193, 29, 253, 162, 77, 154, 125, 79, 27, 128, 12, 210, 209, 96, 40, 119, 35, 83, 195, 128, 11, 102, 232, 53, 100, 12, 107, 58, 82, 88, 76, 221, 249, 187, 185, 121, 139, 160, 144, 107, 5}

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
	cert, err := certificate.MakeBasePrivilegedCert("", "")
	require.NoError(t, err)
	return cert
}

func TestBaseConverter_PemToDer_HappyPath_NonCACert(t *testing.T) {
	pemBytes := getPemBytes(t, nonCADerBytes)

	derBytes, err := certificate.MakeBaseConverter(false).PemToDer(pemBytes)
	assert.NoError(t, err)
	assert.Equal(t, nonCADerBytes, derBytes)
}

func TestBaseConverter_PemToDer_HappyPath_CACert(t *testing.T) {
	cert := makeCACert(t)
	pemBytes := getPemBytes(t, cert.DerBytes())

	derBytes, err := certificate.MakeBaseConverter(true).PemToDer(pemBytes)
	assert.NoError(t, err)
	assert.Equal(t, cert.DerBytes(), derBytes)
}

func TestBaseConverter_PemToDer_IgnoreCACert(t *testing.T) {
	cert := makeCACert(t)
	pemBytes := getPemBytes(t, cert.DerBytes())

	derBytes, err := certificate.MakeBaseConverter(false).PemToDer(pemBytes)
	assert.ErrorContains(t, err, "could not parse out DER bytes")
	assert.Equal(t, certificate.DerBytes{}, derBytes)
}

func TestBaseConverter_PemToDer_CannotParsePEM(t *testing.T) {
	_, err := certificate.MakeBaseConverter(false).
		PemToDer([]byte("not PEM data"))
	assert.ErrorContains(t, err, "no PEM data found")
}

func TestBaseConverter_PemToDer_NoCERTIFICATEBlock(t *testing.T) {
	pemBytes := pem.EncodeToMemory(
		&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{}},
	)

	derBytes, err := certificate.MakeBaseConverter(false).PemToDer(pemBytes)
	assert.ErrorContains(t, err, "could not parse out DER bytes")
	assert.Equal(t, certificate.DerBytes{}, derBytes)
}

func TestBaseConverter_PemToDer_NilPemBytes(t *testing.T) {
	_, err := certificate.MakeBaseConverter(false).PemToDer(nil)
	assert.ErrorContains(t, err, "could not parse out DER bytes")
}

func TestBaseConverter_PemToDer_Errors(t *testing.T) {
	tests := map[string]struct {
		pemBytes []byte
		errRegex string
	}{
		"no PEM data": {
			pemBytes: []byte("no PEM data here"),
			errRegex: "no PEM data found",
		},
		"nil PEM data": {
			pemBytes: nil,
			errRegex: "could not parse out DER bytes",
		},
		"empty PEM data": {
			pemBytes: []byte(""),
			errRegex: "could not parse out DER bytes",
		},
		"non CERTIFICATE PEM data": {
			pemBytes: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: []byte{},
			}),
			errRegex: "could not parse out DER bytes",
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
			"no PEM data found",
			"could not parse out DER bytes",
		)
		assert.NoError(t, err)
		assert.Truef(t, ok, "pemBytes '%#v', err %v", badPEMBytes, pemToDerErr)
	})
}

func TestBaseConverter_DerToPem_HappyPath(t *testing.T) {
	cert := makeCACert(t)

	pemBytes, err := certificate.BaseConverter{}.DerToPem(cert.DerBytes())
	assert.NoError(t, err)
	assert.NotNil(t, pemBytes)

	VerifyCert(t, cert)
}

func FuzzBaseConverter_DerToPem_NeverFails(f *testing.F) {
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

func TestBaseConverter_DerToPemThenPemToDer_Errors(t *testing.T) {
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
