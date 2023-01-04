package nitriding

import (
	"github.com/blocky/nitriding/internal/attestation"
)

type Checker attestation.Checker

func MakeStandaloneChecker() Checker {
	return attestation.StandaloneChecker{}
}

func MakeNitroChecker() Checker {
	return attestation.NitroChecker{}
}
