package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/blocky/nitriding/validation"
)

type SelfSigCert struct {
	derBytes       []byte
	digest         Digest
	privateKey     *ecdsa.PrivateKey
	encodeToMemory func(derBytes DerBytes) (PemBytes, error)
}

func MakeSelfSigCert(
	certOrg string,
	fqdn string,
) (
	SelfSigCert,
	error,
) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return SelfSigCert{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return SelfSigCert{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certOrg},
		},
		DNSNames:              []string{fqdn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		IsCA:                  true,
	}

	var derBytes DerBytes
	derBytes, err = x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return SelfSigCert{}, err
	}

	return MakeSelfSignCertFromRaw(
			derBytes,
			CertDigest(derBytes),
			privateKey,
			EncodeToMemory,
		),
		err
}

func MakeSelfSignCertFromRaw(
	derBytes DerBytes,
	digest Digest,
	privateKey *ecdsa.PrivateKey,
	encodeToMemory func(derBytes DerBytes) (PemBytes, error),
) SelfSigCert {
	return SelfSigCert{
		derBytes:       derBytes,
		digest:         digest,
		privateKey:     privateKey,
		encodeToMemory: encodeToMemory,
	}
}

func MakeSelfSignCertFromFile(
	file *os.File,
) (
	SelfSigCert,
	error,
) {
	bytes := make([]byte, 1024)
	limitReader := io.LimitReader(file, int64(len(bytes)))
	_, err := limitReader.Read(bytes)

	if err != nil {
		return SelfSigCert{}, err
	}
	// Make sure we are working with the correct type of bytes
	pemBytes := PemBytes(bytes)

	derBytes, err := PemToDer(pemBytes)
	if err != nil {
		return SelfSigCert{}, err
	}

	_, err = x509.ParseCertificates(derBytes)
	if err != nil {
		return SelfSigCert{}, err
	}

	digest := CertDigest(derBytes)
	return MakeSelfSignCertFromRaw(derBytes, digest, nil, EncodeToMemory), nil
}

func (cert SelfSigCert) PrivateKey() (*ecdsa.PrivateKey, error) {
	if cert.privateKey != nil {
		return cert.privateKey, nil
	}
	return nil,
		errors.New("cert privateKey is nil, possibly cert loaded from file")
}

var toFileLock sync.Mutex

func (cert SelfSigCert) ToFile(fileName string) (*os.File, error) {
	// Prevent race conditions on writing to the same file
	toFileLock.Lock()
	defer toFileLock.Unlock()

	// It is not clear, as discovered in fuzz tests, what is a permissible
	// file name. So, make sure that a file name will work before trying to
	// work with it.
	fv := validation.MakeFileValidator(validation.LinuxFilePathRegex)
	if err := fv.Validate(fileName); err != nil {
		return nil, fmt.Errorf("file name invalid: %w", err)
	}

	if _, err := os.Stat(fileName); err == nil {
		return nil, fmt.Errorf("file %v already exists", fileName)
	}

	pemFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	err = pemFile.Chmod(0400)
	if err != nil {
		return nil, err
	}
	err = pem.Encode(
		pemFile,
		&pem.Block{Type: "CERTIFICATE", Bytes: cert.derBytes},
	)
	if err != nil {
		return nil, err
	}
	err = pemFile.Close()
	if err != nil {
		return nil, err
	}

	return pemFile, nil
}

func (cert SelfSigCert) ToMemory() (PemBytes, error) {
	return cert.encodeToMemory(cert.derBytes)
}

func (cert SelfSigCert) DerBytes() DerBytes {
	return cert.derBytes
}

func (cert SelfSigCert) Digest() Digest {
	return cert.digest
}
