package standalone_test

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/blocky/nitriding/pkg/nitriding"
	"github.com/go-playground/validator/v10"
)

func Example() {
	// NOTE: this test is intended to run on a local machine and assumes that
	// the server creates self-signed certificates for its TLS connections.
	// The following line allows the test to accept self-signed certificates on
	// TLS connections.
	http.DefaultTransport.(*http.Transport).TLSClientConfig =
		&tls.Config{InsecureSkipVerify: true}

	// Get attester information - url must match the route in main.go
	nonce := nitriding.Nonce{Value: []byte("01234567890123456789")}
	req := "https://localhost:8443/attester?nonce=" + hex.EncodeToString(nonce.Value)
	resp, err := http.Get(req)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("Status code: %v\n", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}

	// Check that the attestation is correctly signed
	checker := nitriding.MakeStandaloneChecker()
	attest, err := checker.CheckAttestDoc(body)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("Attestation verified against its self-signed certificate")

	// Check the request nonce
	if bytes.Compare(nonce.Value, attest.Document.Nonce) == 0 {
		fmt.Println("Request and response nonces match")
	}

	// Check that the TLS certificate used by our connection to the server
	// matches that which the attester uses to connect to us
	attTLSCertFpr := nitriding.TLSCertFpr{Value: attest.Document.UserData}
	err = validator.New().Struct(&attTLSCertFpr)
	if err != nil {
		log.Println(err)
		return
	}
	connTLSCertDigest, err := nitriding.CertDigest(
		resp.TLS.PeerCertificates[0].Raw,
	)
	if err != nil {
		log.Println(err)
		return
	}
	if bytes.Compare(connTLSCertDigest[:], attTLSCertFpr.Value) == 0 {
		fmt.Println("Client and server TLS certificate fingerprints match")
	}

	// Output:
	// Status code: 200
	// Attestation verified against its self-signed certificate
	// Request and response nonces match
	// Client and server TLS certificate fingerprints match
}
