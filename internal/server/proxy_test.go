package server_test

import (
	"regexp"
	"testing"

	"github.com/blocky/nitriding/internal/nitridingtest"
	"github.com/blocky/nitriding/internal/server"
	"github.com/blocky/nitriding/internal/server/system"
	"github.com/blocky/parlor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoOpProxyConfigurator_Interfaces(t *testing.T) {
	proxyBuilder := server.NoOpProxyConfigurator{}
	parlor.AssertType[server.ProxyConfigurator](t, proxyBuilder)
}

func TestNoOpProxyConfigurator_ConfigureSOCKSProxy(t *testing.T) {
	err := server.NoOpProxyConfigurator{}.ConfigureVIProxy()
	assert.NoError(t, err)
}

func TestNoOpProxyConfigurator_ConfigureVIProxy(t *testing.T) {
	err := server.NoOpProxyConfigurator{}.ConfigureVIProxy()
	assert.NoError(t, err)
}

func TestParseSOCKSAddress(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		addr, err := server.ParseSOCKSAddress(
			"socks5://" + system.LocalHostAddr + ":1080",
		)
		assert.NoError(t, err)
		assert.Equal(t, addr.String(), system.LocalHostAddr+":1080")
	})

	tests := map[string]struct {
		url      string
		errRegex string
	}{
		"bad scheme": {
			url:      "bad-scheme://" + system.LocalHostAddr + ":1080",
			errRegex: server.ErrBadSOCKSScheme,
		},
		"bad ip": {
			url:      "socks5://127.0.0.:1080",
			errRegex: "no such host",
		},
		"bad port": {
			url:      "socks5://" + system.LocalHostAddr + ":1080000",
			errRegex: "invalid port",
		},
		"invalid URL escape": {
			url:      "%",
			errRegex: "invalid URL escape",
		},
		"net/url: invalid": {
			url:      "\x19",
			errRegex: "net/url: invalid",
		},
		"bad first path segment": {
			url:      "0:",
			errRegex: "first path segment in URL cannot contain colon",
		},
		"missing protocol scheme": {
			url:      ":0",
			errRegex: "missing protocol scheme",
		},
		"invalid character in host name": {
			url:      "// 0",
			errRegex: "invalid character .* in host name",
		},
		"failed to resolve SOCKSProxy address": {
			url:      "soCks5://0",
			errRegex: "failed to resolve SOCKSProxy address",
		},
		"invalid port": {
			url:      "//:A",
			errRegex: "invalid port",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			addr, err := server.ParseSOCKSAddress(tc.url)
			assert.Nil(t, addr)
			require.Error(t, err)
			assert.Regexp(t, regexp.MustCompile(tc.errRegex), err.Error())
		})
	}
}

func FuzzParseSOCKSAddress(f *testing.F) {
	tests := []struct {
		url string
	}{
		{"socks5://" + system.LocalHostAddr + ":1080"},     // happy path
		{"bad-scheme://" + system.LocalHostAddr + ":1080"}, // bad SOCKSURL scheme
		{"%"},          // invalid URL escape
		{"\x19"},       //net/url: invalid
		{"0:"},         //first path segment in URL cannot contain colon
		{":0"},         //missing protocol scheme
		{"// 0"},       //invalid character " " in host name
		{"soCks5://0"}, //failed to resolve SOCKSProxy address
		{"//:A"},       //invalid port ":A" after host
	}
	for _, tc := range tests {
		f.Add(tc.url)
	}
	f.Fuzz(func(t *testing.T, url string) {
		addr, parseErr := server.ParseSOCKSAddress(url)
		if parseErr == nil {
			assert.NotNil(t, addr)
		} else {
			ok, err := nitridingtest.ErrorMatchesPattern(
				parseErr,
				server.ErrBadSOCKSScheme,
				"invalid URL escape",
				"net/url: invalid",
				"first path segment in URL cannot contain colon",
				"missing protocol scheme",
				"invalid character .* in host name",
				"failed to resolve SOCKSProxy address",
				"invalid port .* after host",
			)
			assert.NoError(t, err)
			assert.Truef(t, ok, "url '%v', error '%v'", url, parseErr)
		}
	})
}

func TestNitroProxyConfigurator_Interfaces(t *testing.T) {
	proxyBuilder := server.NitroProxyConfigurator{}
	parlor.AssertType[server.ProxyConfigurator](t, proxyBuilder)
}

func TestNitroProxyConfigurator_ConfigureSOCKSProxy(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		builder := server.NitroProxyConfigurator{
			SOCKSURL: "socks5://" + system.LocalHostAddr + ":1080",
		}

		err := builder.ConfigureSOCKSProxy()
		assert.NoError(t, err)
	})

	t.Run("parse error", func(t *testing.T) {
		builder := server.NitroProxyConfigurator{
			SOCKSURL: "bad address",
		}

		err := builder.ConfigureSOCKSProxy()
		assert.ErrorContains(t, err, server.ErrBadSOCKSScheme)
	})
}

func TestNitroProxyConfigurator_ConfigureVIProxy(t *testing.T) {
	t.Run("happy path - in enclave", func(t *testing.T) {
		builder := server.NitroProxyConfigurator{
			SOCKSURL:  "socks5://" + system.LocalHostAddr + ":1080",
			InEnclave: true,
		}

		err := builder.ConfigureVIProxy()
		assert.NoError(t, err)
	})

	t.Run("happy path - outside enclave", func(t *testing.T) {
		builder := server.NitroProxyConfigurator{
			SOCKSURL:  "socks5://" + system.LocalHostAddr + ":1080",
			InEnclave: false,
		}

		err := builder.ConfigureVIProxy()
		assert.NoError(t, err)
	})

	t.Run("parse error", func(t *testing.T) {
		builder := server.NitroProxyConfigurator{
			SOCKSURL:  "bad address",
			InEnclave: true,
		}

		err := builder.ConfigureVIProxy()
		assert.ErrorContains(t, err, server.ErrBadSOCKSScheme)
	})

	t.Run("cannot start viproxy", func(t *testing.T) {
		builder := server.NitroProxyConfigurator{
			SOCKSURL:  "socks5://0.0.0.255:1080",
			InEnclave: true,
		}

		err := builder.ConfigureVIProxy()
		assert.ErrorContains(t, err, server.ErrVIProxy)
	})
}
