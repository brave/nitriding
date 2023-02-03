package nitriding

import (
	"github.com/blocky/nitriding/internal/attestation"
)

type Checker attestation.Checker

func MakeSelfSignedChecker() Checker {
	return attestation.SelfSignedChecker{}
}

func MakeNitroChecker() Checker {
	return attestation.NitroChecker{}
}
