package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/blocky/nitriding/internal"
	"github.com/blocky/nitriding/internal/attestation"
	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitriding/internal/server/system"
	"github.com/go-chi/chi/v5"
	"github.com/mdlayher/vsock"
)

const ErrUnknownMethod = "unknown route method"

type Server interface {
	attestation.Attester
	AddRoute(method string, pattern string, handlerFn http.HandlerFunc) error
	CodeURL() string
	InEnclave() bool
	Start() error
	TLSCertFingerprint() (certificate.DigestBytes, error)
}

type BaseServerBuilder struct {
	CodeURL          string
	AppPort          int
	InEnclave        bool
	AttesterBuilder  internal.Builder[attestation.Attester]
	TLSBundleBuilder internal.Builder[TLSBundle]
	ProxyConfigurator
}

func (builder BaseServerBuilder) Build() (Server, error) {
	attester, err := builder.AttesterBuilder.Build()
	if err != nil {
		return nil, err
	}

	tlsConfig, err := builder.TLSBundleBuilder.Build()
	if err != nil {
		return nil, err
	}

	err = builder.ConfigureSOCKSProxy()
	if err != nil {
		return nil, err
	}

	err = builder.ConfigureVIProxy()
	if err != nil {
		return nil, err
	}

	return NewBaseServer(
		builder.CodeURL,
		builder.AppPort,
		tlsConfig,
		attester,
		builder.InEnclave,
	)
}

type BaseServer struct {
	appURL    string
	appPort   int
	attester  attestation.Attester
	cert      func(context.Context) (certificate.Cert, error)
	httpSrv   http.Server
	inEnclave bool
	router    *chi.Mux
}

func NewBaseServer(
	appURL string,
	appPort int,
	tlsBundle TLSBundle,
	attester attestation.Attester,
	inEnclave bool,
) (
	*BaseServer,
	error,
) {
	if attester == nil {
		return nil, errors.New("attester cannot be nil")
	}
	if tlsBundle == nil {
		return nil, errors.New("tlsBundle cannot be nil")
	}
	tlsConfig, err := tlsBundle.GetConfig()
	if err != nil {
		return nil, err
	}

	router := chi.NewRouter()

	srv := &BaseServer{
		appURL:   appURL,
		appPort:  appPort,
		attester: attester,
		cert:     tlsBundle.GetCert, // as function since not known until later
		httpSrv: http.Server{
			Addr:      fmt.Sprintf(":%d", appPort),
			Handler:   router,
			TLSConfig: tlsConfig,
		},
		inEnclave: inEnclave,
		router:    router,
	}

	return srv, nil
}

func NewPartialBaseServerFromRaw(
	attester attestation.Attester,
	cert func(ctx context.Context) (certificate.Cert, error),
) *BaseServer {
	return &BaseServer{
		attester: attester,
		cert:     cert,
	}
}

func (server *BaseServer) InEnclave() bool {
	return server.inEnclave
}

func (server *BaseServer) CodeURL() string {
	return server.appURL
}

func startError(msg string, err error) error {
	return fmt.Errorf("failed to start Server: %v: %w", msg, err)
}

func (server *BaseServer) Start() error {
	if server.inEnclave {
		if err := system.AssignLoAddr(); err != nil {
			return startError("failed to assign loopback address", err)
		}
	}

	// Set file descriptor limit. There's no need to exit if this fails.
	err := system.SetFdLimit(system.DefaultFdSoft, system.DefaultFdHard)
	if err != nil {
		log.Println(err)
	}

	// Start the web server.  If we're inside an enclave, we use a
	// vsock-enabled listener, otherwise a simple tcp listener.
	if server.inEnclave {
		listener, err := vsock.Listen(uint32(server.appPort), nil)
		if err != nil {
			return startError("failed to create vsock listener", err)
		}
		defer func() {
			err = listener.Close()
			if err != nil {
				log.Println(err)
			}
		}()

		log.Printf("Started server at port %v\n", server.appPort)
		return server.httpSrv.ServeTLS(listener, "", "")
	}

	listener, err := net.Listen("tcp", server.httpSrv.Addr)
	if err != nil {
		return startError("failed to create tcp listener", err)
	}
	defer func() {
		err = listener.Close()
		if err != nil {
			log.Println(err)
		}
	}()

	log.Printf("Started server at port %v\n", server.appPort)
	return server.httpSrv.ServeTLS(listener, "", "")
}

func (server *BaseServer) GetAttestDoc(
	nonce,
	publicKey,
	userData []byte,
) (
	[]byte,
	error,
) {
	return server.attester.GetAttestDoc(nonce, publicKey, userData)
}

func (server *BaseServer) TLSCertFingerprint() (
	certificate.DigestBytes,
	error,
) {
	cert, err := server.cert(context.Background())
	if err != nil {
		return certificate.DigestBytes{}, err
	}
	return cert.Digest(), err
}

func (server *BaseServer) AddRoute(
	method, pattern string,
	handlerFn http.HandlerFunc,
) error {
	switch method {
	case http.MethodGet:
		server.router.Get(pattern, handlerFn)
	case http.MethodHead:
		server.router.Head(pattern, handlerFn)
	case http.MethodPost:
		server.router.Post(pattern, handlerFn)
	case http.MethodPut:
		server.router.Put(pattern, handlerFn)
	case http.MethodPatch:
		server.router.Patch(pattern, handlerFn)
	case http.MethodDelete:
		server.router.Delete(pattern, handlerFn)
	case http.MethodConnect:
		server.router.Connect(pattern, handlerFn)
	case http.MethodOptions:
		server.router.Options(pattern, handlerFn)
	case http.MethodTrace:
		server.router.Trace(pattern, handlerFn)
	default:
		return fmt.Errorf("%v: %v", ErrUnknownMethod, method)
	}
	return nil
}
