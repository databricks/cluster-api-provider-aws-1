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

package v1alpha3

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/api/v1alpha3"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha3"
	"sigs.k8s.io/cluster-api/errors"
)

const (
	// ManagedMachinePoolFinalizer allows the controller to clean up resources on delete
	ManagedMachinePoolFinalizer = "awsmanagedmachinepools.infrastructure.cluster.x-k8s.io"
)

// ManagedMachineAMIType specifies which AWS AMI to use for a managed MachinePool
type ManagedMachineAMIType string

const (
	// Al2x86_64 is the default AMI type
	Al2x86_64 ManagedMachineAMIType = "AL2_x86_64"
	// Al2x86_64GPU is the x86-64 GPU AMI type
	Al2x86_64GPU ManagedMachineAMIType = "AL2_x86_64_GPU"
	// Al2Arm64 is the Arm AMI type
	Al2Arm64 ManagedMachineAMIType = "AL2_ARM_64"
)

var (
	// DefaultEKSNodegroupRole is the name of the default IAM role to use for EKS nodegroups
	// if no other role is supplied in the spec and if iam role creation is not enabled. The default
	// can be created using clusterawsadm or created manually
	DefaultEKSNodegroupRole = fmt.Sprintf("eks-nodegroup%s", infrav1.DefaultNameSuffix)
)

// AWSManagedMachinePoolSpec defines the desired state of AWSManagedMachinePool
type AWSManagedMachinePoolSpec struct {
	// EKSNodegroupName specifies the name of the nodegroup in AWS
	// corresponding to this MachinePool. If you don't specify a name
	// then a default name will be created based on the namespace and
	// name of the managed machine pool.
	// +optional
	EKSNodegroupName string `json:"eksNodegroupName,omitempty"`

	// AvailabilityZones is an array of availability zones instances can run in
	AvailabilityZones []string `json:"availabilityZones,omitempty"`

	// SubnetIDs specifies which subnets are used for the
	// auto scaling group of this nodegroup
	// +optional
	SubnetIDs []string `json:"subnetIDs,omitempty"`

	// AdditionalTags is an optional set of tags to add to AWS resources managed by the AWS provider, in addition to the
	// ones added by default.
	// +optional
	AdditionalTags infrav1.Tags `json:"additionalTags,omitempty"`

	// RoleName specifies the name of IAM role for the node group.
	// If the role is pre-existing we will treat it as unmanaged
	// and not delete it on deletion. If the EKSEnableIAM feature
	// flag is true and no name is supplied then a role is created.
	// +optional
	RoleName string `json:"roleName,omitempty"`

	// AMIVersion defines the desired AMI release version. If no version number
	// is supplied then the latest version for the Kubernetes version
	// will be used
	// +kubebuilder:validation:MinLength:=2
	// +optional
	AMIVersion *string `json:"amiVersion,omitempty"`

	// AMIType defines the AMI type
	// +kubebuilder:validation:Enum:=AL2_x86_64;AL2_x86_64_GPU;AL2_ARM_64
	// +kubebuilder:default:=AL2_x86_64
	// +optional
	AMIType *ManagedMachineAMIType `json:"amiType,omitempty"`

	// Labels specifies labels for the Kubernetes node objects
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// DiskSize specifies the root disk size
	// +optional
	DiskSize *int32 `json:"diskSize,omitempty"`

	// InstanceType specifies the AWS instance type
	// +optional
	InstanceType *string `json:"instanceType,omitempty"`

	// Scaling specifies scaling for the ASG behind this pool
	// +optional
	Scaling *ManagedMachinePoolScaling `json:"scaling,omitempty"`

	// RemoteAccess specifies how machines can be accessed remotely
	// +optional
	RemoteAccess *ManagedRemoteAccess `json:"remoteAccess,omitempty"`

	// ProviderIDList are the provider IDs of instances in the
	// autoscaling group corresponding to the nodegroup represented by this
	// machine pool
	// +optional
	ProviderIDList []string `json:"providerIDList,omitempty"`
}

// ManagedMachinePoolScaling specifies scaling options
type ManagedMachinePoolScaling struct {
	MinSize *int32 `json:"minSize,omitempty"`
	MaxSize *int32 `json:"maxSize,omitempty"`
}

// ManagedRemoteAccess specifies remote access settings for EC2 instances
type ManagedRemoteAccess struct {
	// SSHKeyName specifies which EC2 SSH key can be used to access machines.
	// If left empty, the key from the control plane is used.
	SSHKeyName *string `json:"sshKeyName,omitempty"`

	// SourceSecurityGroups specifies which security groups are allowed access
	SourceSecurityGroups []string `json:"sourceSecurityGroups,omitempty"`

	// Public specifies whether to open port 22 to the public internet
	Public bool `json:"public,omitempty"`
}

// AWSManagedMachinePoolStatus defines the observed state of AWSManagedMachinePool
type AWSManagedMachinePoolStatus struct {
	// Ready denotes that the AWSManagedMachinePool nodegroup has joined
	// the cluster
	// +kubebuilder:default=false
	Ready bool `json:"ready"`

	// Replicas is the most recently observed number of replicas.
	// +optional
	Replicas int32 `json:"replicas"`

	// FailureReason will be set in the event that there is a terminal problem
	// reconciling the MachinePool and will contain a succinct value suitable
	// for machine interpretation.
	//
	// This field should not be set for transitive errors that a controller
	// faces that are expected to be fixed automatically over
	// time (like service outages), but instead indicate that something is
	// fundamentally wrong with the Machine's spec or the configuration of
	// the controller, and that manual intervention is required. Examples
	// of terminal errors would be invalid combinations of settings in the
	// spec, values that are unsupported by the controller, or the
	// responsible controller itself being critically misconfigured.
	//
	// Any transient errors that occur during the reconciliation of MachinePools
	// can be added as events to the MachinePool object and/or logged in the
	// controller's output.
	// +optional
	FailureReason *errors.MachineStatusError `json:"failureReason,omitempty"`

	// FailureMessage will be set in the event that there is a terminal problem
	// reconciling the MachinePool and will contain a more verbose string suitable
	// for logging and human consumption.
	//
	// This field should not be set for transitive errors that a controller
	// faces that are expected to be fixed automatically over
	// time (like service outages), but instead indicate that something is
	// fundamentally wrong with the MachinePool's spec or the configuration of
	// the controller, and that manual intervention is required. Examples
	// of terminal errors would be invalid combinations of settings in the
	// spec, values that are unsupported by the controller, or the
	// responsible controller itself being critically misconfigured.
	//
	// Any transient errors that occur during the reconciliation of MachinePools
	// can be added as events to the MachinePool object and/or logged in the
	// controller's output.
	// +optional
	FailureMessage *string `json:"failureMessage,omitempty"`

	// Conditions defines current service state of the managed machine pool
	// +optional
	Conditions clusterv1.Conditions `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:path=awsmanagedmachinepools,scope=Namespaced,categories=cluster-api
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.ready",description="MachinePool ready status"
// +kubebuilder:printcolumn:name="Replicas",type="integer",JSONPath=".status.replicas",description="Number of replicas"

// AWSManagedMachinePool is the Schema for the awsmanagedmachinepools API
type AWSManagedMachinePool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AWSManagedMachinePoolSpec   `json:"spec,omitempty"`
	Status AWSManagedMachinePoolStatus `json:"status,omitempty"`
}

func (r *AWSManagedMachinePool) GetConditions() clusterv1.Conditions {
	return r.Status.Conditions
}

func (r *AWSManagedMachinePool) SetConditions(conditions clusterv1.Conditions) {
	r.Status.Conditions = conditions
}

// +kubebuilder:object:root=true

// AWSManagedMachinePoolList contains a list of AWSManagedMachinePools
type AWSManagedMachinePoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSManagedMachinePool `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AWSManagedMachinePool{}, &AWSManagedMachinePoolList{})
}
