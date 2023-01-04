package nitriding

import (
	"github.com/blocky/nitriding/internal/attestation"
	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitriding/internal/randseed"
	"github.com/blocky/nitriding/internal/server"
)

func NewStandaloneServer(url string, port int) (server.Server, error) {
	inEnclave, err := randseed.InEnclave()
	if err != nil {
		return nil, err
	}

	srvBuilder := server.BaseServerBuilder{
		//Specify the repository of this main() so the "/" tells users what code
		//runs on the server.
		CodeURL: url,
		//Tell the server to handle requests from this port
		AppPort: port,
		//Tell the server if it is running in a Nitro Enclave
		//[can determine dynamically with randseed.InEnclave()]
		InEnclave: inEnclave,
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
				CertOrg: "BLOCKY",
				FQDN:    "example.com",
			},
		},
		//Set up proxies for the server
		//[when running on a NitroEnclave use server.NitroProxyConfigurator]
		ProxyConfigurator: server.NoOpProxyConfigurator{},
	}

	return srvBuilder.Build()
}
