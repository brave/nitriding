package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/blocky/nitriding/pkg/nitriding"
	"github.com/spf13/cobra"
)

var nsm bool

var checkCmd = &cobra.Command{
	Use:   "check attestation",
	Short: "Checks an attestation and prints it as JSON",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var checker nitriding.Checker = nitriding.MakeNitroChecker()
		if !nsm {
			checker = nitriding.MakeSelfSignedChecker()
		}

		attest, err := base64.StdEncoding.DecodeString(args[0])
		if err != nil {
			return fmt.Errorf("could not decode attestation string: %w", err)
		}

		result, err := checker.Check(attest)
		if err != nil {
			return fmt.Errorf("could not verify attestation: %w", err)
		}

		attestDocJSON, err := json.Marshal(result.Document)
		if err != nil {
			return fmt.Errorf("could not marshal document: %w", err)
		}

		_, err = fmt.Fprint(cmd.OutOrStdout(), string(attestDocJSON))
		return err
	},
}

func init() {
	checkCmd.Flags().BoolVar(
		&nsm,
		"nsm",
		true,
		"true: NSM attestation, false: self-signed attestation",
	)
	rootCmd.AddCommand(checkCmd)
}
