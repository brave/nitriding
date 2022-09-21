// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	attestation "github.com/brave/nitriding/attestation"
	mock "github.com/stretchr/testify/mock"

	nitrite "github.com/hf/nitrite"
)

// Checker is an autogenerated mock type for the Checker type
type Checker struct {
	mock.Mock
}

// CheckAttestDoc provides a mock function with given fields: attestDoc
func (_m *Checker) CheckAttestDoc(attestDoc attestation.Doc) (*nitrite.Result, error) {
	ret := _m.Called(attestDoc)

	var r0 *nitrite.Result
	if rf, ok := ret.Get(0).(func(attestation.Doc) *nitrite.Result); ok {
		r0 = rf(attestDoc)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*nitrite.Result)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(attestation.Doc) error); ok {
		r1 = rf(attestDoc)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewChecker interface {
	mock.TestingT
	Cleanup(func())
}

// NewChecker creates a new instance of Checker. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewChecker(t mockConstructorTestingTNewChecker) *Checker {
	mock := &Checker{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
