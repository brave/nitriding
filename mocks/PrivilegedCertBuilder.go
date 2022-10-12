// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	certificate "github.com/brave/nitriding/certificate"
	mock "github.com/stretchr/testify/mock"
)

// PrivilegedCertBuilder is an autogenerated mock type for the PrivilegedCertBuilder type
type PrivilegedCertBuilder struct {
	mock.Mock
}

// MakePrivilegedCert provides a mock function with given fields:
func (_m *PrivilegedCertBuilder) MakePrivilegedCert() (certificate.PrivilegedCert, error) {
	ret := _m.Called()

	var r0 certificate.PrivilegedCert
	if rf, ok := ret.Get(0).(func() certificate.PrivilegedCert); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(certificate.PrivilegedCert)
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

type mockConstructorTestingTNewPrivilegedCertBuilder interface {
	mock.TestingT
	Cleanup(func())
}

// NewPrivilegedCertBuilder creates a new instance of PrivilegedCertBuilder. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewPrivilegedCertBuilder(t mockConstructorTestingTNewPrivilegedCertBuilder) *PrivilegedCertBuilder {
	mock := &PrivilegedCertBuilder{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}