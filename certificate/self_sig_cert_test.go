package certificate_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"regexp"
	"testing"

	"golang.org/x/exp/constraints"

	"github.com/blocky/nitriding/certificate"
	"github.com/blocky/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var goodPEMBytes = []byte{0x2c, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47,
	0x49, 0x4e, 0x1f, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41,
	0x54, 0x44, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0xa, 0x4d, 0x49, 0x49, 0x42,
	0x73, 0x54, 0x43, 0x43, 0x41, 0x54, 0x75, 0x67, 0x41, 0x77, 0x49, 0x41,
	0x41, 0x67, 0x49, 0x51, 0x59, 0x4e, 0x7a, 0x61, 0x43, 0x4a, 0x4c, 0x4c,
	0x37, 0x33, 0x52, 0x4b, 0x62, 0x38, 0x6c, 0x57, 0x47, 0x42, 0x44, 0x4b,
	0x4f, 0x6a, 0x41, 0x4b, 0x42, 0x67, 0x67, 0x71, 0x67, 0x6b, 0x6a, 0x4f,
	0x50, 0x51, 0x51, 0x44, 0x41, 0x7a, 0x41, 0x4b, 0x4d, 0x51, 0x6b, 0x77,
	0xa, 0x42, 0x77, 0x59, 0x44, 0x56, 0x50, 0x51, 0x4b, 0x45, 0x77, 0x41,
	0x77, 0x48, 0x68, 0x63, 0x4e, 0x4c, 0x6a, 0x49, 0x77, 0x4f, 0x44, 0x49,
	0x79, 0x4d, 0x54, 0x63, 0x2f, 0x4d, 0x7a, 0x49, 0x7a, 0x57, 0x68, 0x63,
	0x4e, 0x4d, 0x6a, 0x4c, 0x77, 0x4f, 0x44, 0x45, 0x7a, 0x4d, 0x54, 0x63,
	0x30, 0x4d, 0x79, 0x49, 0x7a, 0x57, 0x6a, 0x41, 0x4c, 0x4d, 0x51, 0x6b,
	0x77, 0x41, 0x77, 0x59, 0x44, 0xa, 0x56, 0x51, 0x51, 0x4b, 0x45, 0x77,
	0x40, 0x77, 0x64, 0x6a, 0x41, 0x51, 0x42, 0x67, 0x63, 0x71, 0x68, 0x6a,
	0x6a, 0x4f, 0x50, 0x51, 0x49, 0x42, 0x42, 0x67, 0x55, 0x72, 0x66, 0x51,
	0x51, 0x41, 0x49, 0x67, 0x4e, 0x69, 0x41, 0x41, 0x52, 0x36, 0x54, 0x31,
	0x7a, 0x52, 0x6d, 0x67, 0x4e, 0x4b, 0x73, 0x71, 0x41, 0x4f, 0x70, 0x63,
	0x66, 0x43, 0x71, 0x33, 0x64, 0x49, 0x72, 0x34, 0x59, 0x4b, 0xa, 0x72,
	0x56, 0x51, 0x70, 0x48, 0x72, 0x38, 0x62, 0x71, 0x53, 0x46, 0x76, 0x78,
	0x77, 0x67, 0x69, 0x55, 0x71, 0x40, 0x62, 0x56, 0x53, 0x48, 0x42, 0x36,
	0x71, 0x32, 0x39, 0x6c, 0x48, 0x42, 0x5a, 0x65, 0x62, 0x66, 0x30, 0x46,
	0x57, 0x67, 0x74, 0x48, 0x4f, 0x48, 0x59, 0x68, 0x58, 0x70, 0x42, 0x65,
	0x74, 0x74, 0x40, 0x43, 0x33, 0x74, 0x54, 0x65, 0x30, 0x30, 0x71, 0x71,
	0x6d, 0x63, 0x64, 0xa, 0x31, 0x79, 0x57, 0x70, 0x7a, 0x32, 0x6a, 0x54,
	0x4e, 0x6b, 0x4c, 0x46, 0x4d, 0x34, 0x49, 0x55, 0x67, 0x56, 0x53, 0x59,
	0x55, 0x71, 0x38, 0x72, 0x2b, 0x51, 0x38, 0x69, 0x35, 0x6d, 0x2f, 0x52,
	0x63, 0x31, 0x42, 0x78, 0x71, 0x34, 0x65, 0x6a, 0x5a, 0x43, 0x42, 0x69,
	0x4d, 0x41, 0x34, 0x47, 0x41, 0x31, 0x55, 0x64, 0x43, 0x77, 0x45, 0x42,
	0x2f, 0x77, 0x51, 0x45, 0x41, 0x77, 0x49, 0x47, 0xa, 0x67, 0x44, 0x41,
	0x54, 0x42, 0x67, 0x4e, 0x56, 0x48, 0x52, 0x55, 0x45, 0x44, 0x44, 0x41,
	0x4b, 0x42, 0x67, 0x67, 0x72, 0x41, 0x67, 0x45, 0x46, 0x42, 0x51, 0x63,
	0x44, 0x41, 0x54, 0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x48, 0x52, 0x4d,
	0x42, 0x41, 0x66, 0x37, 0x45, 0x42, 0x54, 0x41, 0x44, 0x41, 0x51, 0x48,
	0x2f, 0x4d, 0x41, 0x30, 0x47, 0x41, 0x31, 0x55, 0x64, 0x44, 0x67, 0x51,
	0x57, 0x9, 0x42, 0x42, 0x54, 0x65, 0x6e, 0x63, 0x4f, 0x47, 0x50, 0x2b,
	0x37, 0x57, 0x79, 0x41, 0x7a, 0x74, 0x57, 0x37, 0x2f, 0x2b, 0x6e, 0x41,
	0x6f, 0x67, 0x51, 0x7a, 0x52, 0x6c, 0x67, 0x54, 0x41, 0x4c, 0x41, 0x67,
	0x4e, 0x56, 0x48, 0x52, 0x45, 0x45, 0x42, 0x44, 0x41, 0x42, 0x67, 0x67,
	0x41, 0x77, 0x43, 0x67, 0x59, 0x49, 0x4b, 0x6f, 0x59, 0x49, 0x7a, 0x6a,
	0x30, 0x45, 0x41, 0x77, 0x4d, 0x44, 0xa, 0x60, 0x41, 0x41, 0x77, 0x5a,
	0x51, 0x49, 0x77, 0x63, 0x73, 0x5a, 0x57, 0x41, 0x58, 0x63, 0x6f, 0x47,
	0x70, 0x49, 0x75, 0x32, 0x64, 0x6e, 0x6d, 0x79, 0x70, 0x70, 0x6f, 0x75,
	0x4b, 0x77, 0x42, 0x36, 0x2e, 0x66, 0x68, 0x6c, 0x37, 0x75, 0x4c, 0x76,
	0x71, 0x51, 0x57, 0x6a, 0x64, 0x76, 0x45, 0x52, 0x45, 0x61, 0x69, 0x69,
	0x39, 0x68, 0x67, 0x4f, 0x6f, 0x43, 0x36, 0x7a, 0x4f, 0x62, 0x56, 0xa,
	0x4c, 0x41, 0x33, 0x79, 0x57, 0x58, 0x32, 0x75, 0x41, 0x6a, 0x45, 0x41,
	0x37, 0x39, 0x7a, 0x71, 0x66, 0x30, 0x38, 0x41, 0x61, 0x49, 0x49, 0x57,
	0x57, 0x78, 0x6c, 0x31, 0x6c, 0x55, 0x4f, 0x76, 0x59, 0x68, 0x55, 0x33,
	0x68, 0x48, 0x48, 0x47, 0x50, 0x41, 0x66, 0x73, 0x51, 0x79, 0x52, 0x31,
	0x69, 0x6a, 0x54, 0x51, 0x36, 0x32, 0x71, 0x6b, 0x53, 0x2f, 0x71, 0x4e,
	0x48, 0x66, 0x67, 0x47, 0xa, 0x61, 0x30, 0x4d, 0x4a, 0x32, 0x6e, 0x78,
	0x6d, 0x74, 0x75, 0x67, 0x73, 0xa, 0x2c, 0x2d, 0x2d, 0x2d, 0x2d, 0x45,
	0x4e, 0x44, 0x20, 0x43, 0x45, 0x51, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41,
	0x54, 0x45, 0x2d, 0x2d, 0x2c, 0x2d, 0x2d, 0xa}

func TestMakeSelfSigCert_HappyPath(t *testing.T) {
	cert, err := certificate.MakeSelfSigCert("", "")
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	certificate.VerifyCert(t, cert)

	parsedCert, err := x509.ParseCertificate(cert.DerBytes())
	assert.NoError(t, err)
	privateKey, err := cert.PrivateKey()
	require.NoError(t, err)
	assert.Equal(t, parsedCert.PublicKey, &privateKey.PublicKey)
}

func TestMakeSelfSigCert_Errors(t *testing.T) {
	tests := map[string]struct {
		certOrg  string
		fqdn     string
		errRegex string
	}{
		"bad certOrg": {
			certOrg:  "\x92",
			fqdn:     "",
			errRegex: "asn1: string not valid UTF-8",
		},
		"bad fqdn": {
			certOrg:  "",
			fqdn:     "\xff",
			errRegex: "x509: .* cannot be encoded as an IA5String",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cert, err := certificate.MakeSelfSigCert(tc.certOrg, tc.fqdn)
			assert.Error(t, err)
			assert.Regexp(t, regexp.MustCompile(tc.errRegex), err.Error())
			assert.Equal(t, certificate.SelfSigCert{}, cert)
		})
	}
}

func FuzzMakeSelfSigCert(f *testing.F) {
	tests := []struct {
		certOrg string
		fqdn    string
	}{
		{"", ""},     // happy path
		{"\x92", ""}, // asn1: string not valid UTF-8
		{"", "\xff"}, // x509: "\xff" cannot be encoded as an IA5String
	}
	for _, tc := range tests {
		f.Add(tc.certOrg, tc.fqdn)
	}
	f.Fuzz(func(t *testing.T, certOrg string, fqdn string) {
		cert, makeErr := certificate.MakeSelfSigCert(certOrg, fqdn)
		if makeErr == nil {
			certificate.VerifyCert(t, cert)
		} else {
			assert.Equal(t, certificate.SelfSigCert{}, cert)

			ok, err := nitridingtest.ErrorMatchesPattern(
				makeErr,
				"asn1: string not valid UTF-8",
				"x509: .* cannot be encoded as an IA5String",
			)
			assert.NoError(t, err)
			assert.Truef(t, ok, "certOrg '%v', fqdn '%#v', error '%v'", certOrg, fqdn, makeErr)
		}
	})
}

func TestSelfSigCert_PrivateKey_HappyPath(t *testing.T) {
	var digest certificate.Digest
	privateKey := ecdsa.PrivateKey{}
	cert := certificate.MakeSelfSignCertFromRaw(nil, digest, &privateKey, nil)
	privateKeyCopy, err := cert.PrivateKey()
	assert.NoError(t, err)
	assert.Equal(t, &privateKey, privateKeyCopy)
}

func TestSelfSigCert_PrivateKey_NilKey(t *testing.T) {
	var digest certificate.Digest
	cert := certificate.MakeSelfSignCertFromRaw(nil, digest, nil, nil)
	privateKey, err := cert.PrivateKey()
	assert.ErrorContains(t, err, "privateKey is nil")
	assert.Nil(t, privateKey)
}

func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func TestSelfSigCert_ToFile_HappyPath(t *testing.T) {
	certFileName := nitridingtest.ReflectTestName() + ".pem"

	cert, err := certificate.MakeSelfSigCert("", "")
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	file, err := cert.ToFile(certFileName)
	assert.NoError(t, err)
	assert.NotNil(t, file)
	assert.Equal(t, certFileName, file.Name())

	fileStats, err := os.Stat(file.Name())
	assert.NoError(t, err)
	t.Log(int(fileStats.Mode().Perm()))
	assert.Equal(t, 0400, int(fileStats.Mode().Perm()))

	filePEMBytes := make([]byte, min(1024, fileStats.Size()))
	file, err = os.Open(file.Name())
	assert.NoError(t, err)
	limitReader := io.LimitReader(file, 1024)
	n, err := limitReader.Read(filePEMBytes)
	assert.NoError(t, err)
	assert.Equal(t, fileStats.Size(), int64(n))

	pemBytes, err := cert.ToMemory()
	assert.NoError(t, err)
	assert.Equal(t, pemBytes, certificate.PemBytes(filePEMBytes))

	err = os.Remove(file.Name())
	assert.NoError(t, err)
}

func TestSelfSigCert_ToFile_FileExists(t *testing.T) {
	certFileName := nitridingtest.ReflectTestName() + ".pem"
	tmpFile, err := os.Create(certFileName)
	assert.NoError(t, err)

	var digest certificate.Digest
	cert := certificate.MakeSelfSignCertFromRaw(nil, digest, nil, nil)

	_, err = cert.ToFile(certFileName)
	assert.ErrorContains(t, err, "already exists")

	err = os.Remove(tmpFile.Name())
	assert.NoError(t, err)
}

func TestSelfSigCert_ToFile_Errors(t *testing.T) {
	tests := map[string]struct {
		fileName string
		errRegex string
	}{
		"file name invalid": {
			fileName: " ",
			errRegex: "file name invalid",
		},
	}

	cert, err := certificate.MakeSelfSigCert("", "")
	require.NoError(t, err)
	require.NotNil(t, cert)

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := cert.ToFile(tc.fileName)
			assert.Error(t, err)
			assert.Regexp(t, regexp.MustCompile(tc.errRegex), err.Error())
		})
	}
}

// NOTE: This test uses global (file) state and cannot run on multiple workers
// Run it with go test -fuzz=FuzzSelfSigCert_ToFile -parallel=1
func FuzzSelfSigCert_ToFile(f *testing.F) {
	tests := []struct {
		certFileName string
	}{
		{"asdf"}, // happy path
		{" "},    // file name invalid
	}
	for _, tc := range tests {
		f.Add(tc.certFileName)
	}

	cert, err := certificate.MakeSelfSigCert("", "")
	assert.NoError(f, err)
	assert.NotNil(f, cert)

	f.Fuzz(func(t *testing.T, certFileName string) {
		_, err := cert.ToFile(certFileName)
		if err != nil {
			assert.ErrorContainsf(
				t, err, "file name invalid",
				"file name '%v' err: %v", certFileName, err,
			)
		} else {
			fileStats, err := os.Stat(certFileName)
			assert.NoError(t, err)
			assert.Equal(t, 0400, int(fileStats.Mode().Perm()))

			filePEMBytes := make([]byte, min(1024, fileStats.Size()))
			file, err := os.Open(certFileName)
			assert.NoError(t, err)
			limitReader := io.LimitReader(file, 1024)
			n, err := limitReader.Read(filePEMBytes)
			assert.NoError(t, err)
			assert.Equal(t, fileStats.Size(), int64(n))

			pemBytes, err := cert.ToMemory()
			assert.NoError(t, err)
			assert.Equal(t, pemBytes, certificate.PemBytes(filePEMBytes))

			err = os.Remove(certFileName)
			assert.NoError(t, err)
		}
	})
}

func TestMakeSelfSignCert_FromFile_HappyPath(t *testing.T) {
	certFileName := nitridingtest.ReflectTestName() + ".pem"

	origCert, err := certificate.MakeSelfSigCert("", "")
	assert.NoError(t, err)
	certificate.VerifyCert(t, origCert)

	_, err = origCert.ToFile(certFileName)
	assert.NoError(t, err)

	file, err := os.Open(certFileName)
	assert.NoError(t, err)
	certCopy, err := certificate.MakeSelfSignCertFromFile(file)
	assert.NoError(t, err)
	certificate.VerifyCert(t, certCopy)

	assert.Equal(t, origCert.DerBytes(), certCopy.DerBytes())
	assert.Equal(t, origCert.Digest(), certCopy.Digest())
	privateKey, err := certCopy.PrivateKey()
	assert.ErrorContains(t, err, "loaded from file")
	assert.Nil(t, privateKey)

	err = os.Remove(certFileName)
	assert.NoError(t, err)
}

func TestMakeSelfSignCertFromFile_NilFile(t *testing.T) {
	cert, err := certificate.MakeSelfSignCertFromFile(nil)
	assert.ErrorContains(t, err, "invalid argument")
	assert.Equal(t, certificate.SelfSigCert{}, cert)
}

func TestMakeSelfSignCertFromFile_NoPEMData(t *testing.T) {
	certFileName := nitridingtest.ReflectTestName() + ".pem"

	err := os.WriteFile(certFileName, []byte("bad PEM bytes"), 0400)
	assert.NoError(t, err)

	file, err := os.Open(certFileName)
	assert.NoError(t, err)
	cert, err := certificate.MakeSelfSignCertFromFile(file)
	assert.ErrorContains(t, err, "no PEM data found")
	assert.Equal(t, certificate.SelfSigCert{}, cert)

	err = os.Remove(certFileName)
	assert.NoError(t, err)
}

// NOTE: This test uses global (file) state and cannot run on multiple workers
// Run it with go test -fuzz=FuzzSelfSigCert_FromFile -parallel=1
func FuzzSelfSigCert_FromFile(f *testing.F) {
	tests := []struct {
		pemBytes []byte
	}{
		{[]byte("asdf")}, //no PEM data found
		{goodPEMBytes},   //happy path
	}
	for _, tc := range tests {
		f.Add(tc.pemBytes)
	}

	certFileName := nitridingtest.ReflectTestName() + ".pem"

	f.Fuzz(func(t *testing.T, pemBytes []byte) {
		err := os.WriteFile(certFileName, pemBytes, 0400)
		assert.NoError(t, err)

		file, err := os.Open(certFileName)
		assert.NoError(t, err)
		cert, err := certificate.MakeSelfSignCertFromFile(file)
		if err != nil {
			assert.ErrorContainsf(
				t, err, "no PEM data found",
				"file name '%v' err: %v", certFileName, err,
			)
		} else {
			certificate.VerifyCert(t, cert)
		}
		err = os.Remove(certFileName)
		assert.NoError(f, err)
	})
}

func TestSelfSigCert_ToMemory_HappyPath(t *testing.T) {
	expPEMBytes := certificate.PemBytes("some PEM bytes")
	encodeToMemory := func(
		derBytes certificate.DerBytes,
	) (
		certificate.PemBytes,
		error,
	) {
		return expPEMBytes, nil
	}

	var digest certificate.Digest
	cert := certificate.MakeSelfSignCertFromRaw(
		nil,
		digest,
		nil,
		encodeToMemory,
	)
	pemBytes, err := cert.ToMemory()
	assert.NoError(t, err)
	assert.Equal(t, expPEMBytes, pemBytes)
}

func TestSelfSigCert_ToMemory_CannotEncode(t *testing.T) {
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
	cert := certificate.MakeSelfSignCertFromRaw(
		nil,
		digest,
		nil,
		encodeToMemory,
	)
	pemBytes, err := cert.ToMemory()
	assert.ErrorIs(t, err, expErr)
	assert.Nil(t, pemBytes)
}

func TestSelfSigCert_DerBytes_HappyPath(t *testing.T) {
	derBytes := certificate.DerBytes("test bytes")
	digest := certificate.CertDigest(derBytes)
	cert := certificate.MakeSelfSignCertFromRaw(derBytes, digest, nil, nil)
	assert.Equal(t, derBytes, cert.DerBytes())
}

func TestSelfSigCert_Digest_HappyPath(t *testing.T) {
	derBytes := certificate.DerBytes("test bytes")
	digest := certificate.CertDigest(derBytes)
	cert := certificate.MakeSelfSignCertFromRaw(derBytes, digest, nil, nil)
	assert.Equal(t, digest, cert.Digest())
}
