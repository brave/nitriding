package nitriding

import (
	"testing"

	"github.com/blocky/nitriding/internal/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertDigest(t *testing.T) {
	cert, err := certificate.BasePrivilegedCertBuilder{}.Build()
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		digest, err := CertDigest(cert.DerBytes())
		assert.NoError(t, err)
		assert.NotEmpty(t, digest)
	})

	t.Run("nil cert", func(t *testing.T) {
		digest, err := CertDigest(nil)
		assert.Error(t, err)
		assert.Empty(t, digest)
	})
}
