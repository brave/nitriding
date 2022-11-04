// Example demonstrates a [server.Server] running outside a Nitro Enclave.
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/brave/nitriding/attestation"
	"github.com/brave/nitriding/certificate"
	"github.com/brave/nitriding/server"
)

func main() {
	//Create a nitriding server to run outside a Nitro Enclave using a
	//standalone attester.
	srvBuilder := server.BaseServerBuilder{
		//Specify the repository of this main() so the "/" tells users what code
		//runs on the server.
		CodeURL: "github.com/brave/nitriding",
		//Tell the server to handle requests from this port
		AppPort: 8443,
		//Tell the server if it is running in a Nitro Enclave
		//[can determine dynamically with randseed.InEnclave()]
		InEnclave: false,
		//Specify server attester type
		//[use attestation.NitroAttesterBuilder for NSM attestations]
		AttesterBuilder: attestation.StandaloneAttesterBuilder{
			CertDERBytes:       attestation.StandaloneAttesterCert,
			PrivateKeyDERBytes: attestation.StandaloneAttesterPrivateKey,
		},
		//Create a TLS configuration for the server
		//[use server.CertMgrTLSBundleBuilder for Let's Encrypt certificates]
		TLSBundleBuilder: server.SelfSignedTLSBundleBuilder{
			PrivilegedCertBuilder: certificate.BasePrivilegedCertBuilder{
				CertOrg: "Brave Software",
				FQDN:    "example.com",
			},
		},
		//Set up proxies for the server
		//[when running on a NitroEnclave use server.NitroProxyConfigurator]
		ProxyConfigurator: server.NoOpProxyConfigurator{},
	}

	srv, err := srvBuilder.Build()
	if err != nil {
		log.Fatal(fmt.Errorf("could not create server: %w", err))
	}

	err = srv.AddRoute(
		http.MethodGet,
		"/",
		func(writer http.ResponseWriter, request *http.Request) {
			server.IndexHandler(srv, writer, request)
		},
	)
	if err != nil {
		log.Fatal(fmt.Errorf("could not create server: %w", err))
	}

	err = srv.AddRoute(
		http.MethodGet,
		"/attester",
		func(writer http.ResponseWriter, request *http.Request) {
			server.GetAttesterHandler(srv, writer, request)
		},
	)
	if err != nil {
		log.Fatal(fmt.Errorf("could not create server: %w", err))
	}

	err = srv.Start()
	if err != nil {
		log.Fatal(fmt.Errorf("enclave unexpectedly terminated: %w", err))
	}
}
