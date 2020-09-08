/*
Copyright 2020 The Kubernetes Authors.

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

package bootstrap

import iamv1 "sigs.k8s.io/cluster-api-provider-aws/cmd/clusterawsadm/api/iam/v1alpha1"

func (t Template) eksControlPlanePolicies() []string {
	policies := []string{EKSClusterPolicy}
	if t.Spec.ManagedControlPlane.ExtraPolicyAttachments != nil {
		for _, policy := range t.Spec.ManagedControlPlane.ExtraPolicyAttachments {
			additionalPolicy := policy
			policies = append(policies, additionalPolicy)
		}
	}

	return policies
}

func eksAssumeRolePolicy() *iamv1.PolicyDocument {
	return assumeRolePolicy("eks.amazonaws.com")
}
