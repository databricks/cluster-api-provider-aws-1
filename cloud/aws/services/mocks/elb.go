// Copyright © 2018 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by MockGen. DO NOT EDIT.
// Source: sigs.k8s.io/cluster-api-provider-aws/cloud/aws/services (interfaces: ELBInterface)

// Package mocks is a generated GoMock package.
package mocks

import (
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
	v1alpha1 "sigs.k8s.io/cluster-api-provider-aws/cloud/aws/providerconfig/v1alpha1"
)

// MockELBInterface is a mock of ELBInterface interface
type MockELBInterface struct {
	ctrl     *gomock.Controller
	recorder *MockELBInterfaceMockRecorder
}

// MockELBInterfaceMockRecorder is the mock recorder for MockELBInterface
type MockELBInterfaceMockRecorder struct {
	mock *MockELBInterface
}

// NewMockELBInterface creates a new mock instance
func NewMockELBInterface(ctrl *gomock.Controller) *MockELBInterface {
	mock := &MockELBInterface{ctrl: ctrl}
	mock.recorder = &MockELBInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockELBInterface) EXPECT() *MockELBInterfaceMockRecorder {
	return m.recorder
}

// DeleteLoadbalancers mocks base method
func (m *MockELBInterface) DeleteLoadbalancers(arg0 string, arg1 *v1alpha1.Network) error {
	ret := m.ctrl.Call(m, "DeleteLoadbalancers", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteLoadbalancers indicates an expected call of DeleteLoadbalancers
func (mr *MockELBInterfaceMockRecorder) DeleteLoadbalancers(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteLoadbalancers", reflect.TypeOf((*MockELBInterface)(nil).DeleteLoadbalancers), arg0, arg1)
}

// GetAPIServerDNSName mocks base method
func (m *MockELBInterface) GetAPIServerDNSName(arg0 string) (string, error) {
	ret := m.ctrl.Call(m, "GetAPIServerDNSName", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAPIServerDNSName indicates an expected call of GetAPIServerDNSName
func (mr *MockELBInterfaceMockRecorder) GetAPIServerDNSName(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAPIServerDNSName", reflect.TypeOf((*MockELBInterface)(nil).GetAPIServerDNSName), arg0)
}

// ReconcileLoadbalancers mocks base method
func (m *MockELBInterface) ReconcileLoadbalancers(arg0 string, arg1 *v1alpha1.Network) error {
	ret := m.ctrl.Call(m, "ReconcileLoadbalancers", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReconcileLoadbalancers indicates an expected call of ReconcileLoadbalancers
func (mr *MockELBInterfaceMockRecorder) ReconcileLoadbalancers(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReconcileLoadbalancers", reflect.TypeOf((*MockELBInterface)(nil).ReconcileLoadbalancers), arg0, arg1)
}

// RegisterInstanceWithAPIServerELB mocks base method
func (m *MockELBInterface) RegisterInstanceWithAPIServerELB(arg0, arg1 string) error {
	ret := m.ctrl.Call(m, "RegisterInstanceWithAPIServerELB", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// RegisterInstanceWithAPIServerELB indicates an expected call of RegisterInstanceWithAPIServerELB
func (mr *MockELBInterfaceMockRecorder) RegisterInstanceWithAPIServerELB(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterInstanceWithAPIServerELB", reflect.TypeOf((*MockELBInterface)(nil).RegisterInstanceWithAPIServerELB), arg0, arg1)
}
