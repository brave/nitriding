package nitriding

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/blocky/nitriding/internal/server"
	"github.com/go-playground/validator/v10"
)

var (
	ErrBadForm       = "failed to parse POST form data"
	ErrBadNonce      = "unexpected nonce format"
	ErrRespWrite     = "could not write a getResponse"
	ErrAttest        = "cannot obtain attestation document"
	ErrFailedCert    = "cannot obtain certificate"
	ErrNilServer     = "server cannot be nil"
	ErrNilRequest    = "request cannot be nil"
	ErrBadTLSCertFpr = "unexpected TLS certificate fingerprint format"
)

func handleError(
	writer http.ResponseWriter,
	err error,
	errStatus int,
	errMsg string,
) bool {
	returnFromHandler := false

	if err != nil {
		errMsg := fmt.Errorf("%v: %w", errMsg, err).Error()
		http.Error(writer, errMsg, errStatus)
		returnFromHandler = true
	}

	return returnFromHandler
}

func checkHandlerInputs(
	srv server.Server,
	rw http.ResponseWriter,
	req *http.Request,
) bool {
	if srv == nil {
		http.Error(rw, ErrNilServer, http.StatusInternalServerError)
		return false
	}
	if req == nil {
		http.Error(rw, ErrNilRequest, http.StatusInternalServerError)
		return false
	}
	return true
}

func IndexHandler(
	srv server.Server,
	rw http.ResponseWriter,
	req *http.Request,
) {
	if ok := checkHandlerInputs(srv, rw, req); !ok {
		return
	}

	info := ServerInfo{
		InEnclave: srv.InEnclave(),
		CodeURL:   srv.CodeURL(),
	}
	infoBytes, err := json.Marshal(info)
	if handleError(rw, err, http.StatusInternalServerError, ErrRespWrite) {
		return
	}

	_, err = rw.Write(infoBytes)
	if handleError(rw, err, http.StatusInternalServerError, ErrRespWrite) {
		return
	}
}

func GetAttesterHandler(srv server.Server, rw http.ResponseWriter, req *http.Request) {
	if ok := checkHandlerInputs(srv, rw, req); !ok {
		return
	}

	err := req.ParseForm()
	if handleError(rw, err, http.StatusBadRequest, ErrBadForm) {
		return
	}

	validate := validator.New()

	nonceBytes, err := hex.DecodeString(req.URL.Query().Get("nonce"))
	if handleError(rw, err, http.StatusBadRequest, ErrBadNonce) {
		return
	}
	nonce := Nonce{Value: nonceBytes}
	err = validate.Struct(&nonce)
	if handleError(rw, err, http.StatusBadRequest, ErrBadNonce) {
		return
	}

	tlsCertFprBytes, err := srv.TLSCertFingerprint()
	if handleError(rw, err, http.StatusInternalServerError, ErrFailedCert) {
		return
	}
	tlsCertFpr := TLSCertFpr{Value: tlsCertFprBytes[:]}
	err = validate.Struct(&tlsCertFpr)
	if handleError(rw, err, http.StatusInternalServerError, ErrBadTLSCertFpr) {
		return
	}

	// pass in the []byte values once validated
	attestDoc, err := srv.GetAttestDoc(nonce.Value, []byte{}, tlsCertFpr.Value)
	if handleError(rw, err, http.StatusInternalServerError, ErrAttest) {
		return
	}

	_, err = rw.Write(attestDoc)
	if handleError(rw, err, http.StatusInternalServerError, ErrRespWrite) {
		return
	}
}
