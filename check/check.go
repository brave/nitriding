package check

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/brave/nitriding/attestation"
)

func AttestationToJSON(
	checker attestation.Checker,
	attestation string,
) (
	[]byte,
	error,
) {
	attestDoc, err := base64.StdEncoding.DecodeString(attestation)
	if err != nil {
		return nil, fmt.Errorf("could not decode attestation string: %w", err)
	}

	result, err := checker.CheckAttestDoc(attestDoc)
	if err != nil {
		return nil, fmt.Errorf("could not verify attestation: %w", err)
	}

	docJSON, err := json.Marshal(result.Document)
	if err != nil {
		return nil, fmt.Errorf("could not marshal document: %w", err)
	}

	return docJSON, nil
}
