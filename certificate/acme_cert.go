package certificate

type ACMECert struct {
	derBytes       DerBytes
	digest         Digest
	encodeToMemory func(derBytes DerBytes) (PemBytes, error)
}

func MakeACMECert(derBytes DerBytes) ACMECert {
	digest := CertDigest(derBytes)
	return MakeACMECertFromRaw(derBytes, digest, EncodeToMemory)
}

func MakeACMECertFromRaw(
	derBytes DerBytes,
	digest Digest,
	encodeToMemory func(derBytes DerBytes) (PemBytes, error),
) ACMECert {
	return ACMECert{
		derBytes:       derBytes,
		digest:         digest,
		encodeToMemory: encodeToMemory,
	}
}

func (cert ACMECert) ToMemory() (PemBytes, error) {
	return cert.encodeToMemory(cert.derBytes)
}

func (cert ACMECert) DerBytes() DerBytes {
	return cert.derBytes
}
func (cert ACMECert) Digest() Digest {
	return cert.digest
}
