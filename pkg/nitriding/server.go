package nitriding

import (
	"fmt"

	"github.com/blocky/nitriding/internal"
	"github.com/blocky/nitriding/internal/attestation"
	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitriding/internal/server"
	"github.com/hf/nsm"
)

func NewLocalServer(port uint16) (server.Server, error) {
	return NewServer(
		"example.com",
		port,
		"github.com/blocky/nitriding",
		false,
		0,
	)
}

func NewServer(
	fqdn string,
	appPort uint16,
	codeURL string,
	ACME bool,
	socksPort uint16,
) (
	server.Server,
	error,
) {
	inEnclave, err := InEnclave()
	if err != nil {
		return nil, err
	}

	var attesterBuilder internal.Builder[attestation.Attester]
	if inEnclave {
		session, err := nsm.OpenDefaultSession()
		if err != nil {
			return nil, err
		}
		attesterBuilder = attestation.NitroAttesterBuilder{NSMSession: session}
	} else {
		attesterBuilder = attestation.StandaloneAttesterBuilder{
			CertDERBytes:       attestation.StandaloneAttesterCert,
			PrivateKeyDERBytes: attestation.StandaloneAttesterPrivateKey,
		}
	}

	var tlsBundleBuilder internal.Builder[server.TLSBundle]
	if ACME {
		tlsBundleBuilder = &server.CertMgrTLSBundleBuilder{
			CertMgrBuilder: certificate.ACMECertMgrBuilder{
				InEnclave: inEnclave,
				Staging:   true,
				Port:      certificate.ACMEChallengePort,
				FQDN:      fqdn,
			},
			FQDN: fqdn,
		}
	} else {
		tlsBundleBuilder = server.SelfSignedTLSBundleBuilder{
			PrivilegedCertBuilder: certificate.BasePrivilegedCertBuilder{
				CertOrg: "BLOCKY",
				FQDN:    fqdn,
			},
		}
	}

	var proxyConfigurator server.ProxyConfigurator
	if inEnclave {
		proxyConfigurator = server.NitroProxyConfigurator{
			SOCKSURL:    fmt.Sprintf("socks5://127.0.0.1:%v", socksPort),
			VIProxyPort: socksPort,
		}
	} else {
		proxyConfigurator = server.NoOpProxyConfigurator{}
	}

	srvBuilder := server.BaseServerBuilder{
		//Specify the repository of this main() so the "/" tells users what code
		//runs on the server.
		CodeURL: codeURL,
		//Tell the server to handle requests from this appPort
		AppPort: appPort,
		//Tell the server if it is running in a Nitro Enclave
		InEnclave: inEnclave,
		//Specify server attester type
		AttesterBuilder: attesterBuilder,
		//Create a TLS configuration for the server
		TLSBundleBuilder: tlsBundleBuilder,
		//Set up proxies for the server
		ProxyConfigurator: proxyConfigurator,
	}

	return srvBuilder.Build()
}
