package nitriding_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitriding/internal/nitridingtest"
	"github.com/blocky/nitriding/internal/server"
	"github.com/blocky/nitriding/mocks"
	"github.com/blocky/nitriding/pkg/nitriding"
	"github.com/blocky/parlor"
	"github.com/stretchr/testify/assert"
)

const codeURL = "github.com/blocky/nitriding"

func getResponse(
	srv server.Server,
	method string,
	route string,
	handler func(server.Server, http.ResponseWriter, *http.Request),
) *http.Response {
	request := httptest.NewRequest(method, route, nil)
	rec := httptest.NewRecorder()
	handler(srv, rec, request)
	return rec.Result()
}

func responsePayload(t *testing.T, response *http.Response) []byte {
	payload, err := io.ReadAll(response.Body)
	assert.NoError(t, err)
	err = response.Body.Close()
	assert.NoError(t, err)
	return payload
}

func testCheckHandlerInputs(
	t *testing.T,
	handler func(server.Server, http.ResponseWriter, *http.Request),
) {
	endpoint := "/some-endpoint"

	t.Run("nil server", func(t *testing.T) {
		response := getResponse(
			nil,
			http.MethodGet,
			endpoint,
			handler,
		)
		assert.Equal(t, http.StatusInternalServerError, response.StatusCode)

		payload := string(responsePayload(t, response))
		assert.Contains(t, payload, nitriding.ErrNilServer)
	})

	t.Run("nil request", func(t *testing.T) {
		srv := mocks.NewServer(t)

		rec := httptest.NewRecorder()
		handler(srv, rec, nil)
		response := rec.Result()
		assert.Equal(t, http.StatusInternalServerError, response.StatusCode)

		payload := string(responsePayload(t, response))
		assert.Contains(t, payload, nitriding.ErrNilRequest)
	})
}

func TestIndexHandler(t *testing.T) {
	endpoint := "/some-endpoint"
	happyPathTests := map[string]struct {
		inEnclave bool
	}{
		"happy path in enclave":     {inEnclave: true},
		"happy path not in enclave": {inEnclave: false},
	}

	for name, tc := range happyPathTests {
		t.Run(name, func(t *testing.T) {
			srv := mocks.NewServer(t)

			srv.On("InEnclave").Return(tc.inEnclave)
			srv.On("CodeURL").Return(codeURL)

			res := getResponse(
				srv,
				http.MethodGet,
				endpoint,
				nitriding.IndexHandler,
			)
			assert.Equal(t, http.StatusOK, res.StatusCode)

			var info nitriding.ServerInfo
			err := json.Unmarshal(responsePayload(t, res), &info)
			assert.NoError(t, err)
			assert.Equal(t, tc.inEnclave, info.InEnclave)
			assert.Equal(t, codeURL, info.CodeURL)
		})
	}

	testCheckHandlerInputs(t, nitriding.IndexHandler)
}

type GetAttesterHandlerParlor struct {
	parlor.Parlor
	srv *mocks.Server
}

func TestGetAttesterHandlerParlor(t *testing.T) {
	parlor.Run(t, new(GetAttesterHandlerParlor))
}

func (p *GetAttesterHandlerParlor) SetupSubtest() {
	p.srv = mocks.NewServer(p.T())
}

func (p *GetAttesterHandlerParlor) TestGetAttesterHandler() {
	endpoint := "/some-endpoint"
	nonce := nitriding.Nonce{Value: nitridingtest.MakeRandBytes(p.T(), 20)}
	hexNonce := hex.EncodeToString(nonce.Value)
	tlsCertFprBytes := certificate.DigestBytes(
		sha256.Sum256([]byte("certificate")),
	)
	tlsCertFpr := nitriding.TLSCertFpr{Value: tlsCertFprBytes[:]}
	attestation := []byte("attestation")
	expErr := errors.New("expected error")

	p.Run("happy path", func() {
		p.srv.On("TLSCertFingerprint").Return(tlsCertFprBytes, nil)
		p.srv.On("Attest", nonce.Value, []byte{}, tlsCertFpr.Value).
			Return(attestation, nil)

		response := getResponse(
			p.srv,
			http.MethodGet,
			endpoint+"?nonce="+hexNonce,
			nitriding.GetAttesterHandler,
		)
		p.Equal(http.StatusOK, response.StatusCode)

		payload := responsePayload(p.T(), response)
		p.Equal(attestation, payload)
	})

	p.Run("nonce too long", func() {
		response := getResponse(
			p.srv,
			http.MethodGet,
			endpoint+"?nonce="+hexNonce+"AAAAAA",
			nitriding.GetAttesterHandler,
		)
		p.Equal(http.StatusBadRequest, response.StatusCode)

		payload := string(responsePayload(p.T(), response))
		p.Contains(payload, nitriding.ErrBadNonce)
	})

	p.Run("happy path - no nonce", func() {
		p.srv.On("TLSCertFingerprint").Return(tlsCertFprBytes, nil)
		p.srv.On("Attest", []byte{}, []byte{}, tlsCertFpr.Value).
			Return(attestation, nil)

		response := getResponse(
			p.srv,
			http.MethodGet,
			endpoint+"",
			nitriding.GetAttesterHandler,
		)
		p.Equal(http.StatusOK, response.StatusCode)

		payload := responsePayload(p.T(), response)
		p.Equal(attestation, payload)
	})

	p.Run("fail getting TLS cert", func() {
		p.srv.On("TLSCertFingerprint").Return(nil, expErr)

		response := getResponse(
			p.srv,
			http.MethodGet,
			endpoint+"?nonce="+hexNonce,
			nitriding.GetAttesterHandler,
		)
		p.Equal(http.StatusInternalServerError, response.StatusCode)

		payload := string(responsePayload(p.T(), response))
		p.Contains(payload, nitriding.ErrFailedCert)
	})

	p.Run("fail getting attestation", func() {
		p.srv.On("TLSCertFingerprint").Return(tlsCertFprBytes, nil)
		p.srv.On("Attest", nonce.Value, []byte{}, tlsCertFpr.Value).
			Return(nil, expErr)

		response := getResponse(
			p.srv,
			http.MethodGet,
			endpoint+"?nonce="+hexNonce,
			nitriding.GetAttesterHandler,
		)
		p.Equal(http.StatusInternalServerError, response.StatusCode)

		payload := string(responsePayload(p.T(), response))
		p.Contains(payload, nitriding.ErrAttest)
	})

	testCheckHandlerInputs(p.T(), nitriding.GetAttesterHandler)
}
