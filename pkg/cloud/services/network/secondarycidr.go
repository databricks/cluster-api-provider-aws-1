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

package network

import (
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/record"
)

func isInExistingCidrBlocks(cidrBlock string, existingAssociations []*ec2.VpcCidrBlockAssociation) (bool, *ec2.VpcCidrBlockAssociation) {
	for _, existing := range existingAssociations {
		if *existing.CidrBlock == cidrBlock {
			return true, existing
		}
	}
	return false, nil
}

func (s *Service) associateSecondaryCidr() error {
	if s.scope.SecondaryCidrBlocks() == nil {
		return nil
	}

	vpcs, err := s.EC2Client.DescribeVpcs(&ec2.DescribeVpcsInput{
		VpcIds: []*string{&s.scope.VPC().ID},
	})
	if err != nil {
		return err
	}

	if len(vpcs.Vpcs) != 1 {
		return errors.Errorf("VPC not found")
	}

	existingAssociations := vpcs.Vpcs[0].CidrBlockAssociationSet

	for _, cidrBlock := range s.scope.SecondaryCidrBlocks() {
		found, _ := isInExistingCidrBlocks(cidrBlock, existingAssociations)
		if !found {
			out, err := s.EC2Client.AssociateVpcCidrBlock(&ec2.AssociateVpcCidrBlockInput{
				VpcId:     &s.scope.VPC().ID,
				CidrBlock: &cidrBlock,
			})
			if err != nil {
				record.Warnf(s.scope.InfraCluster(), "FailedAssociateSecondaryCidr", "Failed associating secondary CIDR with VPC %v", err)
				return err
			}
			record.Eventf(s.scope.InfraCluster(), "SuccessfulAssociateSecondaryCidr", "Associated secondary CIDR with VPC %q", *out.CidrBlockAssociation.AssociationId)
		}
	}

	return nil
}

func (s *Service) disassociateSecondaryCidr() error {
	if s.scope.SecondaryCidrBlocks() == nil {
		return nil
	}

	vpcs, err := s.EC2Client.DescribeVpcs(&ec2.DescribeVpcsInput{
		VpcIds: []*string{&s.scope.VPC().ID},
	})
	if err != nil {
		return err
	}

	if len(vpcs.Vpcs) != 1 {
		return errors.Errorf("VPC not found")
	}

	existingAssociations := vpcs.Vpcs[0].CidrBlockAssociationSet
	for _, cidrBlock := range s.scope.SecondaryCidrBlocks() {
		found, existing := isInExistingCidrBlocks(cidrBlock, existingAssociations)
		if found {
			_, err := s.EC2Client.DisassociateVpcCidrBlock(&ec2.DisassociateVpcCidrBlockInput{
				AssociationId: existing.AssociationId,
			})
			if err != nil {
				record.Warnf(s.scope.InfraCluster(), "FailedDisassociateSecondaryCidr", "Failed disassociating secondary CIDR with VPC %v", err)
				return err
			}
		}
	}

	return nil
}
