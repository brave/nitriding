// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// Signer is an autogenerated mock type for the Signer type
type Signer struct {
	mock.Mock
}

// MarshalPublicKey provides a mock function with given fields:
func (_m *Signer) MarshalPublicKey() []byte {
	ret := _m.Called()

	var r0 []byte
	if rf, ok := ret.Get(0).(func() []byte); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	return r0
}

// ParsePublicKey provides a mock function with given fields: keyBytes
func (_m *Signer) ParsePublicKey(keyBytes []byte) (interface{}, error) {
	ret := _m.Called(keyBytes)

	var r0 interface{}
	if rf, ok := ret.Get(0).(func([]byte) interface{}); ok {
		r0 = rf(keyBytes)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(keyBytes)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Sign provides a mock function with given fields: data
func (_m *Signer) Sign(data []byte) ([]byte, error) {
	ret := _m.Called(data)

	var r0 []byte
	if rf, ok := ret.Get(0).(func([]byte) []byte); ok {
		r0 = rf(data)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(data)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewSigner interface {
	mock.TestingT
	Cleanup(func())
}

// NewSigner creates a new instance of Signer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewSigner(t mockConstructorTestingTNewSigner) *Signer {
	mock := &Signer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
