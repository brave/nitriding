// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	context "context"

	certificate "github.com/brave/nitriding/certificate"

	mock "github.com/stretchr/testify/mock"

	tls "crypto/tls"
)

// CertMgr is an autogenerated mock type for the CertMgr type
type CertMgr struct {
	mock.Mock
}

// Close provides a mock function with given fields:
func (_m *CertMgr) Close() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetCert provides a mock function with given fields: ctx, fqdn
func (_m *CertMgr) GetCert(ctx context.Context, fqdn string) (certificate.Cert, error) {
	ret := _m.Called(ctx, fqdn)

	var r0 certificate.Cert
	if rf, ok := ret.Get(0).(func(context.Context, string) certificate.Cert); ok {
		r0 = rf(ctx, fqdn)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(certificate.Cert)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, fqdn)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetConfig provides a mock function with given fields:
func (_m *CertMgr) GetConfig() (*tls.Config, error) {
	ret := _m.Called()

	var r0 *tls.Config
	if rf, ok := ret.Get(0).(func() *tls.Config); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*tls.Config)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Start provides a mock function with given fields:
func (_m *CertMgr) Start() <-chan error {
	ret := _m.Called()

	var r0 <-chan error
	if rf, ok := ret.Get(0).(func() <-chan error); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(<-chan error)
		}
	}

	return r0
}

type mockConstructorTestingTNewCertMgr interface {
	mock.TestingT
	Cleanup(func())
}

// NewCertMgr creates a new instance of CertMgr. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewCertMgr(t mockConstructorTestingTNewCertMgr) *CertMgr {
	mock := &CertMgr{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}