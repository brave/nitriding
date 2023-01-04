package nitriding

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

var realAttestString = "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"
var realAttestJSON = "{\"module_id\":\"i-0e811925634bbd863-enc018274a97f16d616\",\"timestamp\":1671224501,\"digest\":\"SHA384\",\"pcrs\":{\"0\":\"XfDu7bXRwyu9cPJfXcnSKOzW1EgJ+BKJ4ZW0sfmyjH8JJSyxlY8Kpv1I1rpXlYBJ\",\"1\":\"xtczvZ5vmCC0U4rFugAGbkRBgHuDAvfvSyswmp5sFR2MN8JdZtFlDMSvcgRXHEjH\",\"10\":\"VWn/J0Iz7Xl4bQbfsHYEu+1eA5XeLN9luF68XZgeKWdAMeYe3d+IkynW8/OQgSnq\",\"11\":\"MatbHVtxnG7BRqw+l1l77d7n/1GSpHaHA1Y67efb8CM/l4ukxUYnnkTY8i+aGekT\",\"12\":\"iLEhZR/mF2+X0v5kCE/MudxXfXtIl24wkOwgvrJHF8KMCuLEj6v0XTNovpYAD6Pg\",\"13\":\"CVqhTM9ZQK43ogfDpKXMPKGK49B+Z9Nsv9ix5riGmRWPetjYZtWAa/1tFFcNeWII\",\"14\":\"KEyczYs2QOP8alAVvFyEDac+nQmSVzlhMDxniiKlOl9L8xaJpHBq+8g2mEr4ESGn\",\"15\":\"nhuuwwVp5mF0ybZWWvypJOoi0ATQBtM8PHB5dezh9q70LGvNNPWRDJ79ovPB39EZ\",\"16\":\"uKRJmMY11vC5itxo1lgAwcZcUsa/vPBVeNwWiysNXCgORm9yM8IL8mccBUhMTnuu\",\"17\":\"83tJXYC2xJD/oyC57sCK3Jjao+kNgUxgt1dRmxevEjd/SSvRhAfta7/8M7+bXuOb\",\"18\":\"dmue1FCG37kwwD7uqtw5IELp/uFa5Aw8O82EF6fixT8lJxg85T+2UPKIhCrGlXDf\",\"19\":\"DUN5LQDqtLKM1A7HnBI1uTnQ+4lf8Fy1KR69OzLmMHsrwzONCY8oGKy2W6TXgSPp\",\"2\":\"66bngcAXUUe5DKgevZZ7mETNWJTDO22bFftrVLtPkvHdtQ3S+7AmeLQawILrPbgU\",\"20\":\"qA+/ELeUPW0cuHGcOsQOwdOLULzujvMZMK/sTYjEv9fTOy3QH284PhN/4Sc4o5Eb\",\"21\":\"hyZ5COM5ddN9M4NOOKnVARJ7p5VreHl6uWBpt0s/7NvfrJvXK3dtSpeXGi61APV8\",\"22\":\"GFFUKeGhp+Z2zglxb50w94PztfwZexgSxyh5+/dh4WukGzHlVHirfj4M+7awLOVy\",\"23\":\"Uoi04M67H7x+pGsVmHPswKgN2v7+xNhYKsD5lBG2XtzadShNIfoRsVHRDdaSssqy\",\"24\":\"4Zy3qdwsof7dRlAj39o8A3bd3fuaOlf1/w0RAedMiZfQOVflUjIkhHT9RyEOgnXA\",\"25\":\"hJ1vRZVYzbpAWUuUX0mEQhER83HgjH3BNbvtW2slTB8aVOBlLfvKCwmPu5Vgp1Lj\",\"26\":\"RcAxMGROgynQ0EOHOPQK6uemPdVvLWnjqsjr0tw30EFJsP0pjQQ/JRKFwPbhjIWl\",\"27\":\"NAFbd9fDiFNITNoT49Yk+TzHTD+zqJlR/Iwk3hFUSH3OVvQ9Uus6RYTes5UZ+spX\",\"28\":\"UBqWhrT+xf9exnRr4o3TxIUdk0KqaX5z0HGfyt6Jmun5Jg+rnLx4BbOfxAmX46a6\",\"29\":\"T2t739tS139ugSKlR6BtALfe+9VDWKv8B99FcfpFJAvU4leuP9v/tJBRQejXK7nF\",\"3\":\"oTk0sLY1bAd9dUiu8rQUnZvEim6U02CcEuzNzK0W5k/ApzF4UO1VEUC5KB3cMo3B\",\"30\":\"C1Ukvce3vYWHCLj4XQk6kNIdW0vFzkvenmsoS2qt/SXT70scLc3n6Dw2UfKHgUO+\",\"31\":\"UmQQ0zNwys+jzr4p0EH0pSkZuwNbxer7F3/5yBfVRRPtHbemzeMkpT89ONJEJKkT\",\"4\":\"lJhkVN0uhf8UPX1u0ktzFhjSjWrsz/7g/BCRpZiYG8HtQr45YlWDgyc9F7eZNGBf\",\"5\":\"UkfRfB2EiaUB4/gwjV4G1ewSa1App4vqhvLhMhkcT+Zs3cQ3vXeZ6+bwmc1eiyKr\",\"6\":\"aapdUHNuQYcWvX4oDU8kQGmJsCvKCIrQeqa99ed6/CxoQSGKYfZYc5OsMNV6J7bo\",\"7\":\"zT6+Sr1o0sLhFeMMvU+FphSditZinO6dbj2PMttpip0JhIBSPtCuby/P36slhVGA\",\"8\":\"qllOHDF1A+13rhQodrnZSEm+e2v3mDfnG1pc9uirgC5243GHwHhI61sEKgTS3NBF\",\"9\":\"9va5vLTImS8sBtrj2QmcwcBYjIjIec76+nzFmy4bRwCu+7r2DEQpMbYkt8R8Viyb\"},\"certificate\":\"MIIBtjCCATygAwIBAgIRAJgmq37MEqkGaXvAKTj/MHEwCgYIKoZIzj0EAwMwCzEJMAcGA1UEChMAMB4XDTIyMTAyNDE2NTY0NVoXDTIzMTAxNTE2NTY0NVowCzEJMAcGA1UEChMAMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPXmlB+wUsQ1fizgpD94axgWXE3mYPxjAAf9M5J8jc01FDLyJ3lsapSoIluCv1g9qZ7ARh4Ha2e4HiVE0XZvjEvS6rujeKQhX+jF3ZcPXANwpUIH3QcwNHAzUs73XcIy4o2QwYjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU42amQN7t9FBfU6Ux6PHapghI2xUwCwYDVR0RBAQwAoIAMAoGCCqGSM49BAMDA2gAMGUCMQDnPhunXNks0AhF4pfrsgSHui2QMzZNEd2jTexmccYSyeJ7Vgx7cFer+lo5A5CeUwQCMBDaP1LdcWO4E13FwHV0Sz9S4E3cwkcMLh9VyV4qLKVqzDmMv7nPS63NHgUUjkAx1g==\",\"cabundle\":null,\"public_key\":\"LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQSs3NW0rcFgxaVhtalB5WW1wekltZGlSRHo2VjZYWFMrSGxUVVhxaTk3d3dSUzRrQUVqUVQKQzFubjJNYTZpZUQ4aDlKUGxCY0dIc1Zpd3lRNWNJY0Rsek4rbVZXWmM3T2hubDhNa3ZzaGt2TG8vYzRlNXVoawp3MWhrcW9NYnAvOE9UcjZvaFZwdFlWRU9kb0d6bG9IYjFYdmFZK2JoNzMxemdsc2ZWalc1dVZHSmcwSDg3K0pkCi94enpqdWR1VWJBS3JaUkRJY1c2d2NNU2lWK0plR0s0dEZ4Tk1jQjlESlZBT1h5Z1FWQ2xrOVRZYkxEa2FZdEUKenNhM0VOMHNlaEM3OXV0elROSmhXcHBOaFVyZkJneTMrU25hcUJOblVvUkJuUVJWa2xtZXlBR3htbSs4Um1pUQpJdW5HSTFOSm84bmZjMzJCa1YwMXREaURVSGprdlRMbitRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K\"}"

func TestCheckCmd(t *testing.T) {
	makeCmd := func() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
		cmd := &cobra.Command{Use: "root"}
		cmd.AddCommand(checkCmd)
		outBuf := bytes.NewBufferString("")
		cmd.SetOut(outBuf)
		errBuf := bytes.NewBufferString("")
		cmd.SetErr(errBuf)
		return cmd, outBuf, errBuf
	}

	t.Run("happy path", func(t *testing.T) {
		cmd, outBuf, errBuf := makeCmd()
		cmd.SetArgs([]string{"check", realAttestString, "--nsm=false"})

		err := cmd.Execute()
		assert.NoError(t, err)
		assert.Equal(t, outBuf.String(), realAttestJSON)
		assert.Equal(t, errBuf.String(), "")
	})

	t.Run("cannot decode attestation", func(t *testing.T) {
		cmd, outBuf, errBuf := makeCmd()
		cmd.SetArgs([]string{"check", "0", "--nsm=false"})

		err := cmd.Execute()
		assert.Error(t, err)
		assert.NotEmpty(t, outBuf.String())
		assert.Contains(t, errBuf.String(), "could not decode attestation")
	})

	t.Run("cannot verify attestation", func(t *testing.T) {
		cmd, outBuf, errBuf := makeCmd()
		cmd.SetArgs([]string{"check", "asdf", "--nsm=false"})

		err := cmd.Execute()
		assert.Error(t, err)
		assert.NotEmpty(t, outBuf.String())
		assert.Contains(t, errBuf.String(), "could not verify attestation")
	})

	t.Run("nsm flag mismatch", func(t *testing.T) {
		cmd, outBuf, errBuf := makeCmd()
		cmd.SetArgs([]string{"check", realAttestString, "--nsm=true"})

		err := cmd.Execute()
		assert.Error(t, err)
		assert.NotEmpty(t, outBuf.String())
		assert.Contains(t, errBuf.String(), "could not verify attestation")
	})
}
