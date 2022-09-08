package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

const certificateValidity = time.Hour * 24 * 356

type PrivilegedCert interface {
	Cert
	PrivateKey() *ecdsa.PrivateKey
	TLSCertificate() (tls.Certificate, error)
}

type PrivilegedCertBuilder interface {
	MakePrivilegedCert() (PrivilegedCert, error)
}

type BasePrivilegedCert struct {
	BaseCert
	privateKey *ecdsa.PrivateKey
}

type BasePrivilegedCertBuilder struct {
	CertOrg string
	FQDN    string
}

func (builder BasePrivilegedCertBuilder) MakePrivilegedCert() (PrivilegedCert, error) {
	return MakeBasePrivilegedCert(builder.CertOrg, builder.FQDN)
}

func MakeBasePrivilegedCert(
	certOrg string,
	fqdn string,
) (
	BasePrivilegedCert,
	error,
) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return BasePrivilegedCert{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return BasePrivilegedCert{}, err
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
		return BasePrivilegedCert{}, err
	}

	baseCert, err := MakeBaseCertFromDerBytes(derBytes)
	if err != nil {
		return BasePrivilegedCert{}, err
	}

	return BasePrivilegedCert{
		BaseCert:   baseCert,
		privateKey: privateKey,
	}, nil
}

func MakeBasePrivilegedCertFromRaw(
	derBytes DerBytes,
	converter Converter,
	privateKey *ecdsa.PrivateKey,
) (
	BasePrivilegedCert,
	error,
) {
	baseCert, err := MakeBaseCertFromDerBytesRaw(derBytes, converter)
	if err != nil {
		return BasePrivilegedCert{}, err
	}
	return BasePrivilegedCert{
		BaseCert:   baseCert,
		privateKey: privateKey,
	}, nil
}

func (cert BasePrivilegedCert) PrivateKey() *ecdsa.PrivateKey {
	return cert.privateKey
}

func (cert BasePrivilegedCert) TLSCertificate() (tls.Certificate, error) {
	if cert.privateKey == nil {
		return tls.Certificate{}, errors.New("cert.privateKey cannot be nil")
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(cert.privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	pemKey := pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes},
	)
	if pemKey == nil {
		return tls.Certificate{},
			errors.New("could not encode private key to memory")
	}

	pemCert, err := cert.PemBytes()
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(pemCert, pemKey)
}
