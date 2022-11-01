package certificate_test

import (
	"context"
	"testing"

	"golang.org/x/crypto/acme/autocert"

	"github.com/brave/nitriding/certificate"
	"github.com/brave/nitriding/nitridingtest"
	"github.com/stretchr/testify/assert"
)

func TestCertCache_Interfaces(t *testing.T) {
	cc := certificate.Cache{}
	nitridingtest.AttestType[autocert.Cache](t, &cc)
}

func TestCache_Put(t *testing.T) {
	key := "key"
	cert := []byte("cert")
	ctx := context.TODO()

	t.Run("happy path", func(t *testing.T) {
		cc := certificate.NewCache()
		err := cc.Put(ctx, key, cert)
		assert.NoError(t, err)

		outCert, err := cc.Get(ctx, key)
		assert.NoError(t, err)
		assert.Equal(t, cert, outCert)
	})

	t.Run("context is done", func(t *testing.T) {
		cc := certificate.NewCache()

		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel()

		err := cc.Put(cancelledCtx, key, cert)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestCache_Get(t *testing.T) {
	key := "key"
	cert := []byte("cert")
	ctx := context.TODO()

	t.Run("happy path", func(t *testing.T) {
		cc := certificate.NewCache()
		err := cc.Put(ctx, key, cert)
		assert.NoError(t, err)

		outCert, err := cc.Get(ctx, key)
		assert.NoError(t, err)
		assert.Equal(t, cert, outCert)
	})

	t.Run("cache miss", func(t *testing.T) {
		cc := certificate.NewCache()
		outCert, err := cc.Get(ctx, key)
		assert.ErrorIs(t, err, autocert.ErrCacheMiss)
		assert.Nil(t, outCert)
	})

	t.Run("context is done", func(t *testing.T) {
		cc := certificate.NewCache()

		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel()

		outCert, err := cc.Get(cancelledCtx, key)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, outCert)
	})
}

func TestCache_Delete(t *testing.T) {
	key := "key"
	cert := []byte("cert")
	ctx := context.TODO()

	t.Run("happy path", func(t *testing.T) {
		cc := certificate.NewCache()
		err := cc.Put(ctx, key, cert)
		assert.NoError(t, err)
		assert.Equal(t, 1, cc.Len())

		err = cc.Delete(ctx, key)
		assert.NoError(t, err)
		assert.Equal(t, 0, cc.Len())
	})

	t.Run("happy path - no key", func(t *testing.T) {
		cc := certificate.NewCache()

		err := cc.Delete(ctx, key)
		assert.NoError(t, err)
		assert.Equal(t, 0, cc.Len())
	})

	t.Run("context is done", func(t *testing.T) {
		cc := certificate.NewCache()

		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel()

		err := cc.Delete(cancelledCtx, key)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestCache_Len(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		cc := certificate.NewCache()
		assert.Equal(t, 0, cc.Len())

		err := cc.Put(context.TODO(), "key", []byte("cert"))
		assert.NoError(t, err)
		assert.Equal(t, 1, cc.Len())
	})
}
