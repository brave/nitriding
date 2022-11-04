package server_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blocky/parlor"
	"github.com/brave/nitriding"
	"github.com/brave/nitriding/attestation"
	"github.com/brave/nitriding/certificate"
	"github.com/brave/nitriding/mocks"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/brave/nitriding/server"
	"github.com/stretchr/testify/assert"
)

const codeURL = "github.com/brave/nitriding"

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
		assert.Contains(t, payload, server.ErrNilServer)
	})

	t.Run("nil request", func(t *testing.T) {
		srv := new(mocks.Server)

		rec := httptest.NewRecorder()
		handler(srv, rec, nil)
		response := rec.Result()
		assert.Equal(t, http.StatusInternalServerError, response.StatusCode)

		payload := string(responsePayload(t, response))
		assert.Contains(t, payload, server.ErrNilRequest)

		srv.AssertExpectations(t)
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
			srv := new(mocks.Server)

			srv.On("InEnclave").Return(tc.inEnclave)
			srv.On("CodeURL").Return(codeURL)

			res := getResponse(
				srv,
				http.MethodGet,
				endpoint,
				server.IndexHandler,
			)
			assert.Equal(t, http.StatusOK, res.StatusCode)

			var info nitriding.ServerInfo
			err := json.Unmarshal(responsePayload(t, res), &info)
			assert.NoError(t, err)
			assert.Equal(t, tc.inEnclave, info.InEnclave)
			assert.Equal(t, codeURL, info.CodeURL)

			srv.AssertExpectations(t)
		})
	}

	testCheckHandlerInputs(t, server.IndexHandler)
}

type GetAttesterHandlerParlor struct {
	parlor.Parlor
	srv *mocks.Server
}

func TestGetAttesterHandlerParlor(t *testing.T) {
	parlor.Run(t, new(GetAttesterHandlerParlor))
}

func (p *GetAttesterHandlerParlor) SetupTest() {
	p.srv = new(mocks.Server)
}

func (p *GetAttesterHandlerParlor) TearDownTest() {
	p.srv.AssertExpectations(p.T())
}

func (p *GetAttesterHandlerParlor) TestGetAttesterHandler() {
	endpoint := "/some-endpoint"
	nonce := nitriding.Nonce{Value: nitridingtest.MakeRandBytes(p.T(), 20)}
	hexNonce := hex.EncodeToString(nonce.Value)
	tlsCertFprBytes := certificate.DigestBytes(
		sha256.Sum256([]byte("certificate")),
	)
	tlsCertFpr := nitriding.TLSCertFpr{Value: tlsCertFprBytes[:]}
	attestDoc := attestation.CBOR("attestation document")
	expErr := errors.New("expected error")

	p.Run("happy path", func() {
		p.srv.On("TLSCertFingerprint").Return(tlsCertFprBytes, nil)
		p.srv.On("GetAttestDoc", nonce.Value, []byte{}, tlsCertFpr.Value).
			Return(attestDoc, nil)

		response := getResponse(
			p.srv,
			http.MethodGet,
			endpoint+"?nonce="+hexNonce,
			server.GetAttesterHandler,
		)
		p.Equal(http.StatusOK, response.StatusCode)

		payload := responsePayload(p.T(), response)
		p.Equal([]byte(attestDoc), payload)
	}, p)

	p.Run("nonce too long", func() {
		response := getResponse(
			p.srv,
			http.MethodGet,
			endpoint+"?nonce="+hexNonce+"AAAAAA",
			server.GetAttesterHandler,
		)
		p.Equal(http.StatusBadRequest, response.StatusCode)

		payload := string(responsePayload(p.T(), response))
		p.Contains(payload, server.ErrBadNonce)
	}, p)

	p.Run("happy path - no nonce", func() {
		p.srv.On("TLSCertFingerprint").Return(tlsCertFprBytes, nil)
		p.srv.On("GetAttestDoc", []byte{}, []byte{}, tlsCertFpr.Value).
			Return(attestDoc, nil)

		response := getResponse(
			p.srv,
			http.MethodGet,
			endpoint+"",
			server.GetAttesterHandler,
		)
		p.Equal(http.StatusOK, response.StatusCode)

		payload := responsePayload(p.T(), response)
		p.Equal([]byte(attestDoc), payload)
	}, p)

	p.Run("fail getting TLS cert", func() {
		p.srv.On("TLSCertFingerprint").Return(nil, expErr)

		response := getResponse(
			p.srv,
			http.MethodGet,
			endpoint+"?nonce="+hexNonce,
			server.GetAttesterHandler,
		)
		p.Equal(http.StatusInternalServerError, response.StatusCode)

		payload := string(responsePayload(p.T(), response))
		p.Contains(payload, server.ErrFailedCert)
	}, p)

	p.Run("fail getting attest doc", func() {
		p.srv.On("TLSCertFingerprint").Return(tlsCertFprBytes, nil)
		p.srv.On("GetAttestDoc", nonce.Value, []byte{}, tlsCertFpr.Value).
			Return(nil, expErr)

		response := getResponse(
			p.srv,
			http.MethodGet,
			endpoint+"?nonce="+hexNonce,
			server.GetAttesterHandler,
		)
		p.Equal(http.StatusInternalServerError, response.StatusCode)

		payload := string(responsePayload(p.T(), response))
		p.Contains(payload, server.ErrAttest)
	}, p)

	testCheckHandlerInputs(p.T(), server.GetAttesterHandler)
}
