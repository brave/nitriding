package server

import (
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/brave/viproxy"
	"github.com/mdlayher/vsock"
)

const (
	ErrBadSOCKSScheme  = "bad SOCKS URL scheme"
	ErrBadSOCKSAddress = "failed to resolve SOCKSProxy address"
	ErrVIProxy         = "failed to start VIProxy"
)

// parentCID determines the CID (analogous to an IP address) of the parent
// EC2 instance.  According to the AWS docs, it is always 3:
// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
const parentCID = 3

type ProxyConfigurator interface {
	ConfigureSOCKSProxy() error
	ConfigureVIProxy() error
}

type NoOpProxyConfigurator struct{}

func (configurator NoOpProxyConfigurator) ConfigureSOCKSProxy() error {
	return nil
}

func (configurator NoOpProxyConfigurator) ConfigureVIProxy() error {
	return nil
}

type NitroProxyConfigurator struct {
	SOCKSURL    string
	VIProxyPort uint16
}

func ParseSOCKSAddress(SOCKSURL string) (*net.TCPAddr, error) {
	addr, err := url.Parse(SOCKSURL)
	if err != nil {
		return nil, err
	}
	if addr.Scheme != "socks5" {
		return nil, fmt.Errorf(
			"%v: should be 'socks5' not '%v'",
			ErrBadSOCKSScheme,
			addr.Scheme,
		)
	}

	inAddr, err := net.ResolveTCPAddr("tcp", addr.Host)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrBadSOCKSAddress, err)
	}

	return inAddr, nil
}

func (configurator NitroProxyConfigurator) ConfigureSOCKSProxy() error {
	_, err := ParseSOCKSAddress(configurator.SOCKSURL)
	if err != nil {
		return err
	}

	// Tell Go's HTTP library to use SOCKS proxy for both HTTP and HTTPS.
	if err := os.Setenv("HTTP_PROXY", configurator.SOCKSURL); err != nil {
		return fmt.Errorf("failed to set env var: %w", err)
	}
	if err := os.Setenv("HTTPS_PROXY", configurator.SOCKSURL); err != nil {
		return fmt.Errorf("failed to set env var: %w", err)
	}
	return nil
}

func (configurator NitroProxyConfigurator) ConfigureVIProxy() error {
	addr, err := ParseSOCKSAddress(configurator.SOCKSURL)
	if err != nil {
		return err
	}

	tuple := &viproxy.Tuple{
		InAddr: addr,
		OutAddr: &vsock.Addr{
			ContextID: uint32(parentCID),
			Port:      uint32(configurator.VIProxyPort),
		},
	}
	proxy := viproxy.NewVIProxy([]*viproxy.Tuple{tuple})
	if err := proxy.Start(); err != nil {
		return fmt.Errorf("%v: %w", ErrVIProxy, err)
	}
	return nil
}
