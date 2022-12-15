package main

import (
	"flag"
	"fmt"
	"log"

	nitriding "github.com/brave/nitriding/attestation"
	"github.com/brave/nitriding/check"
)

var (
	nsm         *bool
	attestation *string
)

func init() {
	nsm = flag.Bool("nsm", true, "parse an NSM attestation")
	attestation = flag.String("attestation", "", "attestation document")
}

func main() {
	flag.Parse()

	var checker nitriding.Checker
	if *nsm {
		checker = nitriding.NitroChecker{}
	} else {
		checker = nitriding.StandaloneChecker{}
	}

	attestJSON, err := check.AttestationToJSON(checker, *attestation)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(attestJSON))
}
