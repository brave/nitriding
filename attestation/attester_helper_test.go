package attestation_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/brave/nitriding/attestation"
	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func TestBaseAttesterHelper_MarshalCBOR(t *testing.T) {
	obj := nitrite.CoseHeader{Alg: cose.AlgorithmES384}
	cborBytesExp, err := cbor.Marshal(obj)
	assert.NoError(t, err)

	cborBytes, err := attestation.BaseAttesterHelper{}.MarshalCBOR(obj)
	assert.NoError(t, err)
	assert.Equal(t, attestation.CBOR(cborBytesExp), cborBytes)
}

func TestBaseAttesterHelper_MakePCRs(t *testing.T) {
	pcrs, err := attestation.BaseAttesterHelper{}.MakePCRs()
	assert.NoError(t, err)
	assert.NotNil(t, pcrs)
}

func TestBaseAttesterHelper_MakeCOSEMessage(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	payload := bytes.Repeat([]byte{0x30}, 48)
	helper := attestation.BaseAttesterHelper{}

	t.Run("happy path", func(t *testing.T) {
		coseMsg, err := helper.MakeCOSEMessage(payload, privateKey)
		assert.NoError(t, err)
		require.NotNil(t, coseMsg)
		assert.Equal(t, payload, coseMsg.Payload)

		coseVerifier, err := cose.NewVerifier(
			attestation.COSEAlgorithm,
			&privateKey.PublicKey,
		)
		assert.NoError(t, err)
		require.NotNil(t, coseVerifier)

		err = coseMsg.Verify(nil, coseVerifier)
		assert.NoError(t, err)
	})

	t.Run("cannot verify with different key", func(t *testing.T) {
		coseMsg, err := helper.MakeCOSEMessage(payload, privateKey)
		assert.NoError(t, err)
		require.NotNil(t, coseMsg)

		diffPrivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, diffPrivateKey)

		coseVerifier, err := cose.NewVerifier(
			attestation.COSEAlgorithm,
			&diffPrivateKey.PublicKey,
		)
		assert.NoError(t, err)
		require.NotNil(t, coseVerifier)

		err = coseMsg.Verify(nil, coseVerifier)
		assert.ErrorContains(t, err, cose.ErrVerification.Error())
	})
}

func FuzzBaseAttesterHelper_MakeCOSEMessage(f *testing.F) {
	tests := []struct {
		payload []byte
	}{
		{bytes.Repeat([]byte{0x30}, 48)}, // happy path
	}
	for _, tc := range tests {
		f.Add(tc.payload)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(f, err)
	require.NotNil(f, privateKey)
	coseVerifier, err := cose.NewVerifier(
		attestation.COSEAlgorithm,
		&privateKey.PublicKey,
	)
	require.NoError(f, err)
	require.NotNil(f, coseVerifier)
	helper := attestation.BaseAttesterHelper{}

	f.Fuzz(
		func(t *testing.T, payload []byte) {
			coseMsg, err := helper.MakeCOSEMessage(payload, privateKey)
			assert.NoError(t, err)
			require.NotNil(t, coseMsg)
			assert.Equal(t, payload, coseMsg.Payload)
			assert.NoError(t, coseMsg.Verify(nil, coseVerifier))
		},
	)
}
