package check_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	nitriding "github.com/brave/nitriding/attestation"
	"github.com/brave/nitriding/check"
	"github.com/brave/nitriding/mocks"
	"github.com/hf/nitrite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestationToJSON(t *testing.T) {
	attestDoc := nitriding.CBOR("attestDoc")
	attestation := base64.StdEncoding.EncodeToString(attestDoc)
	publicKey := []byte("public key")
	result := &nitrite.Result{
		Document: &nitrite.Document{
			PublicKey: publicKey,
		},
	}

	t.Run("happy path", func(t *testing.T) {
		checker := new(mocks.Checker)

		checker.On("CheckAttestDoc", attestDoc).Return(result, nil)

		docJSON, err := check.AttestationToJSON(checker, attestation)
		assert.NoError(t, err)
		require.NotNil(t, docJSON)

		var doc nitrite.Document
		err = json.Unmarshal(docJSON, &doc)
		assert.NoError(t, err)
		assert.Equal(t, publicKey, doc.PublicKey)

		checker.AssertExpectations(t)
	})

	t.Run("cannot decode attestation", func(t *testing.T) {
		checker := new(mocks.Checker)

		docJSON, err := check.AttestationToJSON(checker, "0")
		assert.Error(t, err)
		require.Nil(t, docJSON)

		checker.AssertExpectations(t)
	})

	t.Run("cannot verify attestation", func(t *testing.T) {
		checker := new(mocks.Checker)

		checker.On("CheckAttestDoc", attestDoc).Return(nil, errors.New("error"))

		docJSON, err := check.AttestationToJSON(checker, attestation)
		assert.Error(t, err)
		require.Nil(t, docJSON)

		checker.AssertExpectations(t)
	})
}
