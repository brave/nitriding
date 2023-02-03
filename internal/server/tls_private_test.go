package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blocky/nitriding/internal/certificate"
	"github.com/blocky/nitriding/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMakeCertMgrTLSBundle_GetCachedCert(t *testing.T) {
	fqdn := "test.com"

	t.Run("happy path", func(t *testing.T) {
		certMgr := mocks.NewCertMgr(t)

		certMgr.On("GetCert", mock.Anything, fqdn).
			Return(certificate.BaseCert{}, nil)

		tlsBundle := MakeCertMgrTLSBundle(fqdn, certMgr)

		cert, err := tlsBundle.getCachedCert(time.Second)
		assert.NoError(t, err)
		assert.NotNil(t, cert)
	})

	t.Run("context timeout", func(t *testing.T) {
		certMgr := mocks.NewCertMgr(t)

		certMgr.On("GetCert", mock.Anything, fqdn).
			Return(nil, context.DeadlineExceeded)

		tlsBundle := MakeCertMgrTLSBundle(fqdn, certMgr)

		cert, err := tlsBundle.getCachedCert(time.Second)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, cert)
	})
}

func TestErrChanOrTimeout(t *testing.T) {
	timeout := 10 * time.Millisecond
	expErr := errors.New("expected error")

	t.Run("happy path - timeout", func(t *testing.T) {
		errChan := make(chan error, 1)
		defer close(errChan)

		go func() {
			defer func() { _ = recover() }() //if channel closed during sleep
			time.Sleep(2 * timeout)
			errChan <- expErr
		}()

		err := errChanOrTimeout(errChan, timeout)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("happy path - errChan error", func(t *testing.T) {
		errChan := make(chan error, 1)
		defer close(errChan)

		go func() {
			errChan <- expErr
		}()

		err := errChanOrTimeout(errChan, timeout)
		assert.ErrorIs(t, err, expErr)
	})
}
