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

package eks

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/version"

	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/controllers/noderefutil"
	capierrors "sigs.k8s.io/cluster-api/errors"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/api/v1beta1"
	ekscontrolplanev1 "sigs.k8s.io/cluster-api-provider-aws/controlplane/eks/api/v1beta1"
	expinfrav1 "sigs.k8s.io/cluster-api-provider-aws/exp/api/v1beta1"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/awserrors"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/converters"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/services/wait"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/record"
)

const (
	NodeGroupInitializationTaintKey = "databricks.com/eks-nodegroup-initialization"
	NodeGroupInitializationTaintValue = "true"
)

func (s *NodegroupService) describeNodegroup() (*eks.Nodegroup, error) {
	eksClusterName := s.scope.KubernetesClusterName()
	nodegroupName := s.scope.NodegroupName()
	s.scope.V(2).Info("describing eks node group", "cluster", eksClusterName, "nodegroup", nodegroupName)
	input := &eks.DescribeNodegroupInput{
		ClusterName:   aws.String(eksClusterName),
		NodegroupName: aws.String(nodegroupName),
	}

	out, err := s.EKSClient.DescribeNodegroup(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case eks.ErrCodeResourceNotFoundException:
				return nil, nil
			default:
				return nil, errors.Wrap(err, "failed to describe nodegroup")
			}
		} else {
			return nil, errors.Wrap(err, "failed to describe nodegroup")
		}
	}

	return out.Nodegroup, nil
}

func (s *NodegroupService) describeASGs(ng *eks.Nodegroup) (*autoscaling.Group, error) {
	eksClusterName := s.scope.KubernetesClusterName()
	nodegroupName := s.scope.NodegroupName()
	s.scope.V(2).Info("describing node group ASG", "cluster", eksClusterName, "nodegroup", nodegroupName)

	if len(ng.Resources.AutoScalingGroups) == 0 {
		return nil, nil
	}

	input := &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []*string{
			ng.Resources.AutoScalingGroups[0].Name,
		},
	}

	out, err := s.AutoscalingClient.DescribeAutoScalingGroups(input)
	switch {
	case awserrors.IsNotFound(err):
		return nil, nil
	case err != nil:
		return nil, errors.Wrap(err, "failed to describe ASGs")
	case len(out.AutoScalingGroups) == 0:
		return nil, errors.Wrap(err, "no ASG found")
	}

	return out.AutoScalingGroups[0], nil
}

func (s *NodegroupService) scalingConfig() *eks.NodegroupScalingConfig {
	var replicas int32 = 1
	if s.scope.MachinePool.Spec.Replicas != nil {
		replicas = *s.scope.MachinePool.Spec.Replicas
	}
	cfg := eks.NodegroupScalingConfig{
		DesiredSize: aws.Int64(int64(replicas)),
	}
	scaling := s.scope.ManagedMachinePool.Spec.Scaling
	if scaling == nil {
		return &cfg
	}
	if scaling.MaxSize != nil {
		cfg.MaxSize = aws.Int64(int64(*scaling.MaxSize))
	}
	if scaling.MaxSize != nil {
		cfg.MinSize = aws.Int64(int64(*scaling.MinSize))
	}
	return &cfg
}

func (s *NodegroupService) roleArn() (*string, error) {
	var role *iam.Role
	if s.scope.RoleName() != "" {
		var err error
		role, err = s.GetIAMRole(s.scope.RoleName())
		if err != nil {
			return nil, errors.Wrapf(err, "error getting node group IAM role: %s", s.scope.RoleName())
		}
	}
	return role.Arn, nil
}

func ngTags(key string, additionalTags infrav1.Tags) map[string]string {
	tags := additionalTags.DeepCopy()
	tags[infrav1.ClusterAWSCloudProviderTagKey(key)] = string(infrav1.ResourceLifecycleOwned)
	return tags
}

func (s *NodegroupService) remoteAccess() (*eks.RemoteAccessConfig, error) {
	pool := s.scope.ManagedMachinePool.Spec
	if pool.RemoteAccess == nil {
		return nil, nil
	}

	controlPlane := s.scope.ControlPlane

	// SourceSecurityGroups is validated to be empty if PublicAccess is true
	// but just in case we use an empty list to take advantage of the documented
	// API behavior
	var sSGs = []string{}

	if !pool.RemoteAccess.Public {
		sSGs = pool.RemoteAccess.SourceSecurityGroups
		// We add the EKS created cluster security group to the allowed security
		// groups by default to prevent the API default of 0.0.0.0/0 from taking effect
		// in case SourceSecurityGroups is empty
		clusterSG, ok := controlPlane.Status.Network.SecurityGroups[ekscontrolplanev1.SecurityGroupCluster]
		if !ok {
			return nil, errors.Errorf("%s security group not found on control plane", ekscontrolplanev1.SecurityGroupCluster)
		}
		sSGs = append(sSGs, clusterSG.ID)

		if controlPlane.Spec.Bastion.Enabled {
			bastionSG, ok := controlPlane.Status.Network.SecurityGroups[infrav1.SecurityGroupBastion]
			if !ok {
				return nil, errors.Errorf("%s security group not found on control plane", infrav1.SecurityGroupBastion)
			}
			sSGs = append(
				sSGs,
				bastionSG.ID,
			)
		}
	}

	sshKeyName := pool.RemoteAccess.SSHKeyName
	if sshKeyName == nil {
		sshKeyName = controlPlane.Spec.SSHKeyName
	}

	return &eks.RemoteAccessConfig{
		SourceSecurityGroups: aws.StringSlice(sSGs),
		Ec2SshKey:            sshKeyName,
	}, nil
}

func (s *NodegroupService) createNodegroup() (*eks.Nodegroup, error) {
	eksClusterName := s.scope.KubernetesClusterName()
	nodegroupName := s.scope.NodegroupName()
	additionalTags := s.scope.AdditionalTags()
	roleArn, err := s.roleArn()
	if err != nil {
		return nil, err
	}
	managedPool := s.scope.ManagedMachinePool.Spec
	tags := ngTags(s.scope.ClusterName(), additionalTags)

	remoteAccess, err := s.remoteAccess()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create remote access configuration")
	}

	subnets, err := s.scope.SubnetIDs()
	if err != nil {
		return nil, fmt.Errorf("failed getting nodegroup subnets: %w", err)
	}
	input := &eks.CreateNodegroupInput{
		ScalingConfig: s.scalingConfig(),
		ClusterName:   aws.String(eksClusterName),
		NodegroupName: aws.String(nodegroupName),
		Subnets:       aws.StringSlice(subnets),
		NodeRole:      roleArn,
		Labels:        aws.StringMap(managedPool.Labels),
		Tags:          aws.StringMap(tags),
		RemoteAccess:  remoteAccess,
	}
	if managedPool.AMIType != nil {
		input.AmiType = aws.String(string(*managedPool.AMIType))
	}
	if managedPool.DiskSize != nil {
		input.DiskSize = aws.Int64(int64(*managedPool.DiskSize))
	}
	// we should not set instance type in the launch template if we are using hte machine pool spec fields
	if managedPool.AWSLaunchTemplate.InstanceType != "" && (managedPool.InstanceType != nil || managedPool.InstanceTypes != nil) {
		return nil, errors.New("cannot specify InstanceType or InstanceTypes field if launch template field is set.")
	}
	// we should only have Instance type or Instance Types field set in managedPool spec not both
	if managedPool.InstanceType != nil && managedPool.InstanceTypes != nil {
		return nil, errors.New("cannot specify both InstanceType and InstanceTypes field at the same time.")
	}
	if managedPool.InstanceType != nil {
		input.InstanceTypes = []*string{managedPool.InstanceType}
	}
	if managedPool.InstanceTypes != nil {
		input.InstanceTypes = managedPool.InstanceTypes
	}
	if len(managedPool.Taints) > 0 {
		s.Info("adding taints to nodegroup", "nodegroup", nodegroupName)
		taints, err := converters.TaintsToSDK(managedPool.Taints)
		if err != nil {
			return nil, fmt.Errorf("converting taints: %w", err)
		}
		input.Taints = taints
	}
	if s.scope.AllowRecreateNodeGroups() {
		input.Taints = append(input.Taints, &eks.Taint{
			Effect: aws.String(eks.TaintEffectNoSchedule),
			Key:    aws.String(NodeGroupInitializationTaintKey),
			Value:  aws.String(NodeGroupInitializationTaintValue),
		})
	}
	if managedPool.CapacityType != nil {
		capacityType, err := converters.CapacityTypeToSDK(*managedPool.CapacityType)
		if err != nil {
			return nil, fmt.Errorf("converting capacity type: %w", err)
		}
		input.CapacityType = aws.String(capacityType)
	}
	if managedPool.AWSLaunchTemplate != nil {
		input.LaunchTemplate = &eks.LaunchTemplateSpecification{
			Id:      s.scope.ManagedMachinePool.Status.LaunchTemplateID,
			Version: s.scope.ManagedMachinePool.Status.LaunchTemplateVersion,
		}
	}

	if err := input.Validate(); err != nil {
		return nil, errors.Wrap(err, "created invalid CreateNodegroupInput")
	}

	out, err := s.EKSClient.CreateNodegroup(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			// TODO
			case eks.ErrCodeResourceNotFoundException:
				return nil, nil
			default:
				return nil, errors.Wrap(err, "failed to create nodegroup")
			}
		} else {
			return nil, errors.Wrap(err, "failed to create nodegroup")
		}
	}

	return out.Nodegroup, nil
}

func (s *NodegroupService) deleteNodegroup(isRecreate bool) (reterr error) {
	eksClusterName := s.scope.KubernetesClusterName()
	nodegroupName := s.scope.NodegroupName()
	deletingReason := clusterv1.DeletingReason
	if isRecreate {
		deletingReason = expinfrav1.EKSNodegroupRecreatingReason
	}
	if err := s.scope.NodegroupReadyFalse(deletingReason, ""); err != nil {
		return err
	}
	defer func() {
		if reterr != nil {
			record.Warnf(
				s.scope.ManagedMachinePool, "FailedDeleteEKSNodegroup", "Failed to delete EKS nodegroup %s: %v", s.scope.NodegroupName(), reterr,
			)
			if err := s.scope.NodegroupReadyFalse("DeletingFailed", reterr.Error()); err != nil {
				reterr = err
			}
		} else {
			deletedReason := clusterv1.DeletedReason
			if isRecreate {
				deletedReason = expinfrav1.EKSNodegroupRecreatingReason
			}
			if err := s.scope.NodegroupReadyFalse(deletedReason, ""); err != nil {
				reterr = err
			}
		}
	}()
	input := &eks.DeleteNodegroupInput{
		ClusterName:   aws.String(eksClusterName),
		NodegroupName: aws.String(nodegroupName),
	}
	if err := input.Validate(); err != nil {
		return errors.Wrap(err, "created invalid DeleteNodegroupInput")
	}

	_, err := s.EKSClient.DeleteNodegroup(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			// TODO
			case eks.ErrCodeResourceNotFoundException:
				return nil
			default:
				return errors.Wrap(err, "failed to delete nodegroup")
			}
		} else {
			return errors.Wrap(err, "failed to delete nodegroup")
		}
	}

	return nil
}

func (s *NodegroupService) reconcileNodegroupVersion(ng *eks.Nodegroup) error {
	var specVersion *version.Version
	if s.scope.Version() != nil {
		specVersion = parseEKSVersion(*s.scope.Version())
	}
	ngVersion := version.MustParseGeneric(*ng.Version)
	specAMI := s.scope.ManagedMachinePool.Spec.AMIVersion
	ngAMI := *ng.ReleaseVersion
	statusLaunchTemplateVersion := s.scope.ManagedMachinePool.Status.LaunchTemplateVersion
	var ngLaunchTemplateVersion *string
	if ng.LaunchTemplate != nil {
		ngLaunchTemplateVersion = ng.LaunchTemplate.Version
	}

	eksClusterName := s.scope.KubernetesClusterName()
	if (specVersion != nil && ngVersion.LessThan(specVersion)) || (specAMI != nil && *specAMI != ngAMI) || (statusLaunchTemplateVersion != nil && *statusLaunchTemplateVersion != *ngLaunchTemplateVersion) {
		input := &eks.UpdateNodegroupVersionInput{
			ClusterName:   aws.String(eksClusterName),
			NodegroupName: aws.String(s.scope.NodegroupName()),
		}

		var updateMsg string
		// Either update k8s version or AMI version
		switch {
		case specVersion != nil && ngVersion.LessThan(specVersion):
			// NOTE: you can only upgrade increments of minor versions. If you want to upgrade 1.14 to 1.16 we
			// need to go 1.14-> 1.15 and then 1.15 -> 1.16.
			input.Version = aws.String(versionToEKS(ngVersion.WithMinor(ngVersion.Minor() + 1)))
			updateMsg = fmt.Sprintf("to version %s", *input.Version)
		case specAMI != nil && *specAMI != ngAMI:
			input.ReleaseVersion = specAMI
			updateMsg = fmt.Sprintf("to AMI version %s", *input.ReleaseVersion)
		case statusLaunchTemplateVersion != nil && *statusLaunchTemplateVersion != *ngLaunchTemplateVersion:
			input.LaunchTemplate = &eks.LaunchTemplateSpecification{
				Id:      s.scope.ManagedMachinePool.Status.LaunchTemplateID,
				Version: statusLaunchTemplateVersion,
			}
			updateMsg = fmt.Sprintf("to launch template version %s", *statusLaunchTemplateVersion)
		}

		if err := wait.WaitForWithRetryable(wait.NewBackoff(), func() (bool, error) {
			if _, err := s.EKSClient.UpdateNodegroupVersion(input); err != nil {
				if aerr, ok := err.(awserr.Error); ok {
					return false, aerr
				}
				return false, err
			}
			record.Eventf(s.scope.ManagedMachinePool, "SuccessfulUpdateEKSNodegroup", "Updated EKS nodegroup %s %s", eksClusterName, updateMsg)
			return true, nil
		}); err != nil {
			record.Warnf(s.scope.ManagedMachinePool, "FailedUpdateEKSNodegroup", "failed to update the EKS nodegroup %s %s: %v", eksClusterName, updateMsg, err)
			return errors.Wrapf(err, "failed to update EKS nodegroup")
		}
	}
	return nil
}

func createLabelUpdate(specLabels map[string]string, ng *eks.Nodegroup) *eks.UpdateLabelsPayload {
	current := ng.Labels
	payload := eks.UpdateLabelsPayload{
		AddOrUpdateLabels: map[string]*string{},
	}
	for k, v := range specLabels {
		if currentV, ok := current[k]; !ok || currentV == nil || v != *currentV {
			payload.AddOrUpdateLabels[k] = aws.String(v)
		}
	}
	for k := range current {
		if _, ok := specLabels[k]; !ok {
			payload.RemoveLabels = append(payload.RemoveLabels, aws.String(k))
		}
	}
	if len(payload.AddOrUpdateLabels) > 0 || len(payload.RemoveLabels) > 0 {
		return &payload
	}
	return nil
}

func getNodeGroupHealthIssueMessage(ng *eks.Nodegroup) (code string, message string) {
	if ng.Health == nil || len(ng.Health.Issues) == 0 {
		return "", ""
	}
	return *ng.Health.Issues[0].Code, *ng.Health.Issues[0].Message
}

func getNodeGroupHealthIssueReason(code string, message string) string {
	if code == "" {
		return ""
	}
	if code == "AsgInstanceLaunchFailures" {
		if strings.Contains(message, "InsufficientInstanceCapacity") {
			return expinfrav1.EKSNodegroupInsufficientCapacityReason
		} else if strings.Contains(message, "InvalidAMIID") {
			return expinfrav1.EKSNodegroupInvalidAMIReason
		} else if strings.Contains(message, "ReservationCapacityExceeded") {
			return expinfrav1.EKSNodegroupReservationCapacityExceededReason
		} else if strings.Contains(message, "Instance became unhealthy") {
			return expinfrav1.EKSNodegroupUnhealthyInstanceesReason
		} else if strings.Contains(message, "InvalidAMIID") {
			return expinfrav1.EKSNodegroupInvalidAMIReason
		} else if strings.Contains(message, "Unsupported - Your requested instance type") {
			return expinfrav1.EKSNodegroupUnsupportedInstanceTypeReason
		} else if strings.Contains(message, "VcpuLimitExceeded") {
			return expinfrav1.EKSNodegroupVcpuLimitExceededReason
		} else if strings.Contains(message, "Amazon EKS or one or more of your managed nodes is unable to communicate with your Kubernetes cluster API server.") {
			return expinfrav1.EKSNodegroupUnhealthyInstanceesReason
		} else {
			return expinfrav1.EKSNodegroupAsgInstanceLaunchFailureReason
		}
	} else if code == "InsufficientFreeAddresses" {
		return expinfrav1.EKSNodegroupInsufficientFreeAddressesReason
	} else if code == "ClusterUnreachable" {
		return expinfrav1.EKSNodegroupClusterUnreachableReason
	} else if code == "SourceEc2LaunchTemplateNotFound" {
		return expinfrav1.EKSNodegroupLaunchTemplateNotFoundReason
	} else if code == "NodeCreationFailure" {
		return expinfrav1.EKSNodegroupUnhealthyInstanceesReason
	} else if code == "AutoScalingGroupInvalidConfiguration" {
		if strings.Contains(message, "Couldn't terminate instances because instance scale-in protection is enabled for the Auto Scaling group.") {
			return expinfrav1.EKSNodegroupInstanceScaleInProtectionEnabledReason
		} else {
			return expinfrav1.EKSNodegroupAsgInvalidConfigurationReason
		}
	}
	return expinfrav1.EKSNodegroupStatusNotReadyReason
}

func isRecoverableFailureReason(failureReason string) bool {
	return failureReason == expinfrav1.EKSNodegroupInsufficientCapacityReason ||
		failureReason == expinfrav1.EKSNodegroupVcpuLimitExceededReason ||
		failureReason == expinfrav1.EKSNodegroupReservationCapacityExceededReason ||
		failureReason == expinfrav1.EKSNodegroupClusterUnreachableReason
}

func (s *NodegroupService) createTaintsUpdate(specTaints expinfrav1.Taints, ng *eks.Nodegroup) (*eks.UpdateTaintsPayload, error) {
	s.V(2).Info("Creating taints update for node group", "name", *ng.NodegroupName, "num_current", len(ng.Taints), "num_required", len(specTaints))
	current, err := converters.TaintsFromSDK(ng.Taints)
	if err != nil {
		return nil, fmt.Errorf("converting taints: %w", err)
	}
	payload := eks.UpdateTaintsPayload{}
	for _, specTaint := range specTaints {
		st := specTaint.DeepCopy()
		if !current.Contains(st) {
			sdkTaint, err := converters.TaintToSDK(*st)
			if err != nil {
				return nil, fmt.Errorf("converting taint to sdk: %w", err)
			}
			payload.AddOrUpdateTaints = append(payload.AddOrUpdateTaints, sdkTaint)
		}
	}
	for _, currentTaint := range current {
		ct := currentTaint.DeepCopy()
		if !specTaints.Contains(ct) {
			sdkTaint, err := converters.TaintToSDK(*ct)
			if err != nil {
				return nil, fmt.Errorf("converting taint to sdk: %w", err)
			}
			payload.RemoveTaints = append(payload.RemoveTaints, sdkTaint)
		}
	}
	if len(payload.AddOrUpdateTaints) > 0 || len(payload.RemoveTaints) > 0 {
		s.V(2).Info("Node group taints update required", "name", *ng.NodegroupName, "addupdate", len(payload.AddOrUpdateTaints), "remove", len(payload.RemoveTaints))
		return &payload, nil
	}

	s.V(2).Info("No updates required for node group taints", "name", *ng.NodegroupName)
	return nil, nil
}

func (s *NodegroupService) reconcileNodegroupConfig(ng *eks.Nodegroup) error {
	eksClusterName := s.scope.KubernetesClusterName()
	s.V(2).Info("reconciling node group config", "cluster", eksClusterName, "name", *ng.NodegroupName)

	managedPool := s.scope.ManagedMachinePool.Spec
	input := &eks.UpdateNodegroupConfigInput{
		ClusterName:   aws.String(eksClusterName),
		NodegroupName: aws.String(managedPool.EKSNodegroupName),
	}
	var needsUpdate bool
	if labelPayload := createLabelUpdate(managedPool.Labels, ng); labelPayload != nil {
		s.V(2).Info("Nodegroup labels need an update", "nodegroup", ng.NodegroupName)
		input.Labels = labelPayload
		needsUpdate = true
	}
	taintsPayload, err := s.createTaintsUpdate(managedPool.Taints, ng)
	if err != nil {
		return fmt.Errorf("creating taints update payload: %w", err)
	}
	if taintsPayload != nil {
		s.V(2).Info("nodegroup taints need updating")
		input.Taints = taintsPayload
		needsUpdate = true
	}

	desiredMaxSize := int64(aws.Int32Value(managedPool.Scaling.MaxSize))
	desiredMinSize := int64(aws.Int32Value(managedPool.Scaling.MinSize))
	if managedPool.Scaling != nil {
		if *ng.Status == eks.NodegroupStatusDegraded {
			desiredMaxSize, desiredMinSize = getScalingConfigForDegradedNodeGroup(ng, managedPool)
		}

		currentMaxSize := aws.Int64Value(ng.ScalingConfig.MaxSize)
		currentMinSize := aws.Int64Value(ng.ScalingConfig.MinSize)
		if (currentMaxSize != desiredMaxSize) || (currentMinSize != desiredMinSize) {
			s.V(2).Info("Nodegroup min/max differ from spec, updating scaling configuration", "nodegroup", ng.NodegroupName)
			input.ScalingConfig = s.scalingConfig()
			input.ScalingConfig.MaxSize = aws.Int64(desiredMaxSize)
			input.ScalingConfig.MinSize = aws.Int64(desiredMinSize)
			// Only set the desired size if the desiredSize is invalid (i.e. < minSize or > maxSize)
			// Otherwise, we set it to nil since we want it to be controlled by cluster autoscaler and not reconciled
			if aws.Int64Value(ng.ScalingConfig.DesiredSize) < aws.Int64Value(input.ScalingConfig.MinSize) {
				input.ScalingConfig.DesiredSize = input.ScalingConfig.MinSize
			} else if aws.Int64Value(ng.ScalingConfig.DesiredSize) > aws.Int64Value(input.ScalingConfig.MaxSize) {
				input.ScalingConfig.DesiredSize = input.ScalingConfig.MaxSize
			} else {
				input.ScalingConfig.DesiredSize = nil
			}
			needsUpdate = true
		}
	}
	if !needsUpdate {
		s.V(2).Info("node group config update not needed", "cluster", eksClusterName, "name", *ng.NodegroupName)
		return nil
	}
	if err := input.Validate(); err != nil {
		return errors.Wrap(err, "created invalid UpdateNodegroupConfigInput")
	}

	_, err = s.EKSClient.UpdateNodegroupConfig(input)
	if err != nil {
		return errors.Wrap(err, "failed to update nodegroup config")
	}

	return nil
}

// If the nodegroup is in a degraded state due to recoverable issues (e.g. insufficient capacity), we need to temporarily adjust the scaling configuration, in hope that the nodegroup will recover.
// This helper function computes the new scaling configuration so that the desired and current size is different and would trigger an EKS update.
func getScalingConfigForDegradedNodeGroup(ng *eks.Nodegroup, managedPool expinfrav1.AWSManagedMachinePoolSpec) (newDesiredMaxSize int64, newDesiredMinSize int64) {
	currentMaxSize := aws.Int64Value(ng.ScalingConfig.MaxSize)
	currentMinSize := aws.Int64Value(ng.ScalingConfig.MinSize)
	desiredMaxSize := int64(aws.Int32Value(managedPool.Scaling.MaxSize))
	desiredMinSize := int64(aws.Int32Value(managedPool.Scaling.MinSize))
	newDesiredMaxSize = desiredMaxSize
	newDesiredMinSize = desiredMinSize

	reason := getNodeGroupHealthIssueReason(getNodeGroupHealthIssueMessage(ng))
	// TODO: check if we can handle EKSNodegroupReservationCapacityExceeded as well
	if isRecoverableFailureReason(reason) {
		if desiredMaxSize != currentMaxSize || desiredMinSize != currentMinSize {
			// desired size is already different from current size, so we don't need to change anything
		} else {
			if desiredMinSize > 0 {
				// desired min size is greater than 0, so we can safely decrease it
				newDesiredMinSize = desiredMinSize - 1
			} else {
				if desiredMaxSize > 0 {
					// desired min size is 0, we can safely increase it
					newDesiredMinSize = desiredMinSize + 1
				} else {
					// in this case, desired min size == desired max size == 0, so we can't do anything
				}
			}
		}
	}

	return newDesiredMaxSize, newDesiredMinSize
}

func (s *NodegroupService) reconcileNodegroup() (shouldRequeue bool, err error) {
	ng, err := s.describeNodegroup()
	if err != nil {
		return false, errors.Wrap(err, "failed to describe nodegroup")
	}

	if eksClusterName, eksNodegroupName := s.scope.KubernetesClusterName(), s.scope.NodegroupName(); ng == nil {
		ng, err = s.createNodegroup()
		if err != nil {
			return false, errors.Wrap(err, "failed to create nodegroup")
		}
		s.scope.Info("Created EKS nodegroup in AWS", "cluster-name", eksClusterName, "nodegroup-name", eksNodegroupName)
	} else {
		tagKey := infrav1.ClusterAWSCloudProviderTagKey(s.scope.ClusterName())
		ownedTag := ng.Tags[tagKey]
		if ownedTag == nil {
			return false, errors.Wrapf(err, "owner of %s mismatch: %s", eksNodegroupName, s.scope.ClusterName())
		}
		s.scope.V(2).Info("Found owned EKS nodegroup in AWS", "cluster-name", eksClusterName, "nodegroup-name", eksNodegroupName)
	}

	if err := s.setStatus(ng); err != nil {
		return false, errors.Wrap(err, "failed to set status")
	}

	switch *ng.Status {
	case eks.NodegroupStatusCreating, eks.NodegroupStatusUpdating, eks.NodegroupStatusDeleting:
		return true, nil
	case eks.NodegroupStatusCreateFailed: // In case node group with launch template create failed, ng.Version will be nil, and deferencing it in reconcileNodegroupVersion will throw error
		if s.scope.AllowRecreateNodeGroups() && isNodeGroupInitializing(ng) && isRecoverableFailureReason(getNodeGroupHealthIssueReason(getNodeGroupHealthIssueMessage(ng))) {
			record.Warnf(s.scope.ManagedMachinePool, "RecreateFailedEKSNodegroup", "EKS nodegroup %s of cluster %s is in CREATE_FAILED state, recreating", *ng.NodegroupName, *ng.ClusterName)
			s.deleteNodegroup(true)
		}
		return true, nil
	case eks.NodegroupStatusDegraded:
		break
	case eks.NodegroupStatusActive:
		if isNodeGroupInitializing(ng) {
			shouldRequeue = true
		}
	default:
		break
	}

	if err != nil {
		return false, errors.Wrap(err, "failed to wait for nodegroup to be active")
	}
	/* 
	// This is to handle the case for EKS MLserving case using dblet when node pool is created by dblet but Kaas is managing the nodepool CR and it may cause version is different. 
	// From Kaas, we do not need to upgrade node pool but rather always create a new node pool

	if err := s.reconcileNodegroupVersion(ng); err != nil {
		return errors.Wrap(err, "failed to reconcile nodegroup version")
	}
	*/

	if err := s.reconcileNodegroupConfig(ng); err != nil {
		return false, errors.Wrap(err, "failed to reconcile nodegroup config")
	}

	if err := s.reconcileTags(ng); err != nil {
		return false, errors.Wrapf(err, "failed to reconcile nodegroup tags")
	}

	if err := s.reconcileASGTags(ng); err != nil {
		return false, errors.Wrapf(err, "failed to reconcile asg tags")
	}

	return shouldRequeue, nil
}

func (s *NodegroupService) removeNodeGroupInitializationTaint(ng *eks.Nodegroup) error {
	input := &eks.UpdateNodegroupConfigInput{
		ClusterName:   ng.ClusterName,
		NodegroupName: ng.NodegroupName,
	}
	taintsPayload := eks.UpdateTaintsPayload{}
	taintsPayload.RemoveTaints = append(taintsPayload.RemoveTaints, &eks.Taint{
		Effect: aws.String(eks.TaintEffectNoSchedule),
		Key:    aws.String(NodeGroupInitializationTaintKey),
		Value:  aws.String(NodeGroupInitializationTaintValue),
	})
	input.Taints = &taintsPayload
	_, err := s.EKSClient.UpdateNodegroupConfig(input)
	if err != nil {
		return errors.Wrap(err, "failed to remove nodegroup initialization taint")
	}
	return nil
}

func isNodeGroupInitializing(ng *eks.Nodegroup) bool {
	for _, taint := range ng.Taints {
		if *taint.Key == NodeGroupInitializationTaintKey {
			return true
		}
	}
	return false
}

func (s *NodegroupService) setStatus(ng *eks.Nodegroup) error {
	managedPool := s.scope.ManagedMachinePool
	healthCode, healthMessage := getNodeGroupHealthIssueMessage(ng)
	healthReason := getNodeGroupHealthIssueReason(healthCode, healthMessage)
	nodeGroupInitializing := isNodeGroupInitializing(ng)
	switch *ng.Status {
	case eks.NodegroupStatusDeleting:
		managedPool.Status.Ready = false
	case eks.NodegroupStatusCreateFailed:
		failureReason := capierrors.MachineStatusError(healthReason)
		failureMessage := fmt.Sprintf("Nodegroup %s: %s", *ng.Status, healthMessage)
		// If create failed and the underlying issue is recoverable, delete the nodegroup and let CAPA recreate one
		if s.scope.AllowRecreateNodeGroups() && nodeGroupInitializing && isRecoverableFailureReason(healthReason) {
			failureReason = capierrors.MachineStatusError(expinfrav1.EKSNodegroupRecreatingReason)
			failureMessage = fmt.Sprintf("Nodegroup create failed, trying to recreate the node group: %s", healthMessage)
		}
		managedPool.Status.Ready = false
		managedPool.Status.FailureReason = &failureReason
		managedPool.Status.FailureMessage = &failureMessage
	case eks.NodegroupStatusDegraded, eks.NodegroupStatusDeleteFailed:
		managedPool.Status.Ready = false
		failureReason := capierrors.MachineStatusError(healthReason)
		failureMessage := fmt.Sprintf("Nodegroup %s: %s", *ng.Status, healthMessage)
		managedPool.Status.FailureReason = &failureReason
		managedPool.Status.FailureMessage = &failureMessage
	case eks.NodegroupStatusActive:
		// If we just created the node group, we need to remove the taint that we added
		if nodeGroupInitializing {
			s.removeNodeGroupInitializationTaint(ng)
			managedPool.Status.Ready = false
			failureReason := capierrors.MachineStatusError(expinfrav1.EKSNodegroupInitializingReason)
			failureMessage := fmt.Sprintf("Nodegroup initializing")
			managedPool.Status.FailureReason = &failureReason
			managedPool.Status.FailureMessage = &failureMessage
		} else {
			managedPool.Status.Ready = true
		}
	case eks.NodegroupStatusCreating:
		managedPool.Status.Ready = false
		failureReason := capierrors.MachineStatusError("")
		failureMessage := ""
		managedPool.Status.FailureReason = &failureReason
		managedPool.Status.FailureMessage = &failureMessage
	case eks.NodegroupStatusUpdating:
		managedPool.Status.Ready = true
	default:
		return errors.Errorf("unexpected EKS nodegroup status %s", *ng.Status)
	}
	if managedPool.Status.Ready && ng.Resources != nil && len(ng.Resources.AutoScalingGroups) > 0 {
		req := autoscaling.DescribeAutoScalingGroupsInput{}
		for _, asg := range ng.Resources.AutoScalingGroups {
			req.AutoScalingGroupNames = append(req.AutoScalingGroupNames, asg.Name)
		}
		groups, err := s.AutoscalingClient.DescribeAutoScalingGroups(&req)
		if err != nil {
			return errors.Wrap(err, "failed to describe AutoScalingGroup for nodegroup")
		}

		var replicas int32
		var providerIDList []string
		for _, group := range groups.AutoScalingGroups {
			replicas += int32(len(group.Instances))
			for _, instance := range group.Instances {
				id, err := noderefutil.NewProviderID(fmt.Sprintf("aws://%s/%s", *instance.AvailabilityZone, *instance.InstanceId))
				if err != nil {
					s.Error(err, "couldn't create provider ID for instance", "id", *instance.InstanceId)
					continue
				}
				providerIDList = append(providerIDList, id.String())
			}
		}
		managedPool.Spec.ProviderIDList = providerIDList
		managedPool.Status.Replicas = replicas
	}
	if err := s.scope.PatchObject(); err != nil {
		return errors.Wrap(err, "failed to update nodegroup")
	}
	return nil
}
