/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package scope

import (
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"k8s.io/klog/v2/klogr"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/api/v1beta1"
	expinfrav1 "sigs.k8s.io/cluster-api-provider-aws/exp/api/v1beta1"
	expclusterv1 "sigs.k8s.io/cluster-api/exp/api/v1beta1"
)

var (
	AWSManagedControlPlaneKind = "AWSManagedControlPlane"
)

// LaunchTemplateScope defines a scope defined around a launch template.
type LaunchTemplateScope struct {
	logr.Logger

	AWSLaunchTemplate *expinfrav1.AWSLaunchTemplate
	MachinePool       *expclusterv1.MachinePool
	InfraCluster      EC2Scope
	name              string
	additionalTags    infrav1.Tags
}

// LaunchTemplateScopeParams defines a scope defined around a launch template.
type LaunchTemplateScopeParams struct {
	Logger *logr.Logger

	AWSLaunchTemplate *expinfrav1.AWSLaunchTemplate
	MachinePool       *expclusterv1.MachinePool
	InfraCluster      EC2Scope
	name              string
	additionalTags    infrav1.Tags
}

// NewLaunchTemplateScope creates a new LaunchTemplateScope from the supplied parameters.
func NewLaunchTemplateScope(params LaunchTemplateScopeParams) (*LaunchTemplateScope, error) {
	if params.MachinePool == nil {
		return nil, errors.New("machinepool is required when creating a LaunchTemplateScope")
	}
	if params.InfraCluster == nil {
		return nil, errors.New("cluster is required when creating a LaunchTemplateScope")
	}

	if params.Logger == nil {
		log := klogr.New()
		params.Logger = &log
	}

	return &LaunchTemplateScope{
		Logger: *params.Logger,

		AWSLaunchTemplate: params.AWSLaunchTemplate,
		MachinePool:       params.MachinePool,
		InfraCluster:      params.InfraCluster,
		name:              params.name,
		additionalTags:    params.additionalTags,
	}, nil
}

func (m *LaunchTemplateScope) IsEKSManaged() bool {
	return m.InfraCluster.InfraCluster().GetObjectKind().GroupVersionKind().Kind == AWSManagedControlPlaneKind
}

func (m *LaunchTemplateScope) Name() string {
	return m.name
}

func (m *LaunchTemplateScope) AdditionalTags() infrav1.Tags {
	tags := make(infrav1.Tags)

	// Start with the cluster-wide tags...
	tags.Merge(m.InfraCluster.AdditionalTags())
	// ... and merge in the Machine's
	tags.Merge(m.additionalTags)

	return tags
}
