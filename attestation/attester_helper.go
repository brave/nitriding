package attestation

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	ErrCBORMarshal  = "could not marshal CBOR header"
	ErrPCRRead      = "could not read random PCR bytes"
	ErrSignerCreate = "could not create COSE signer"
	ErrMsgSign      = "could not sign COSE message"
)

const (
	// Determined experimentally when parsing an NSM attestation
	numPCRs = 32
	// https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html
	pcrLen = 48
)

type AttesterHelper interface {
	MarshalCBOR(obj any) (cborBytes []byte, err error)
	MakePCRs() (pcrs map[uint][]byte, err error)
	MakeCOSEMessage(
		payload []byte,
		privateKey *ecdsa.PrivateKey,
	) (
		coseMsg *cose.Sign1Message,
		err error,
	)
}

type BaseAttesterHelper struct {
}

func (_ BaseAttesterHelper) MarshalCBOR(obj any) ([]byte, error) {
	cborBytes, err := cbor.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrCBORMarshal, err)
	}
	return cborBytes, nil
}

func (_ BaseAttesterHelper) MakePCRs() (map[uint][]byte, error) {
	pcrs := make(map[uint][]byte)
	for i := uint(0); i < numPCRs; i++ {
		pcr := make([]byte, pcrLen)
		_, err := rand.Read(pcr)
		if err != nil {
			return nil, fmt.Errorf("%v: %w", ErrPCRRead, err)
		}
		pcrs[i] = pcr
	}
	return pcrs, nil
}

func (_ BaseAttesterHelper) MakeCOSEMessage(
	payload []byte,
	privateKey *ecdsa.PrivateKey,
) (
	*cose.Sign1Message,
	error,
) {
	coseMsg := cose.NewSign1Message()
	coseSigner, err := cose.NewSigner(COSEAlgorithm, privateKey)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrSignerCreate, err)
	}
	coseMsg.Headers = cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: coseSigner.Algorithm(),
		},
	}
	coseMsg.Payload = payload
	err = coseMsg.Sign(rand.Reader, nil, coseSigner)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrMsgSign, err)
	}

	return coseMsg, nil
}
