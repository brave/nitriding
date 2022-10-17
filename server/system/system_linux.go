package system

import (
	"fmt"
	"net"

	"github.com/milosgajdos/tenus"
)

const (
	ErrLinkCreate  = "could not create link to the loopback interface"
	ErrSubnetParse = "could not parse link source subnet"
	ErrLinkIP      = "could not link source subnet to the loopback interface"
	ErrLinkUp      = "could not stand up link"
)

// AssignLoAddr assigns an IP address to the loopback interface, which is
// necessary because Nitro enclaves don't do that out-of-the-box.  We need the
// loopback interface because we run a simple TCP proxy that listens on
// 127.0.0.1:1080 and converts AF_INET to AF_VSOCK.
func AssignLoAddr() error {
	sourceSubnet := LocalHostAddr + "/8"
	l, err := tenus.NewLinkFrom("lo")
	if err != nil {
		return fmt.Errorf("%v: %w", ErrLinkCreate, err)
	}

	addr, network, err := net.ParseCIDR(sourceSubnet)
	if err != nil {
		return fmt.Errorf("%v: %w", ErrSubnetParse, err)
	}

	if err = l.SetLinkIp(addr, network); err != nil {
		return fmt.Errorf("%v: %w", ErrLinkIP, err)
	}

	if err = l.SetLinkUp(); err != nil {
		return fmt.Errorf("%v: %w", ErrLinkUp, err)
	}
	return nil
}
