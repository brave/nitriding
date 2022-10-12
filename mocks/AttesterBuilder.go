// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	attestation "github.com/brave/nitriding/attestation"
	mock "github.com/stretchr/testify/mock"
)

// AttesterBuilder is an autogenerated mock type for the AttesterBuilder type
type AttesterBuilder struct {
	mock.Mock
}

// MakeAttester provides a mock function with given fields:
func (_m *AttesterBuilder) MakeAttester() (attestation.Attester, error) {
	ret := _m.Called()

	var r0 attestation.Attester
	if rf, ok := ret.Get(0).(func() attestation.Attester); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(attestation.Attester)
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

type mockConstructorTestingTNewAttesterBuilder interface {
	mock.TestingT
	Cleanup(func())
}

// NewAttesterBuilder creates a new instance of AttesterBuilder. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAttesterBuilder(t mockConstructorTestingTNewAttesterBuilder) *AttesterBuilder {
	mock := &AttesterBuilder{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}