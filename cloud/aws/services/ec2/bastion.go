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

package ec2

import (
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"sigs.k8s.io/cluster-api-provider-aws/cloud/aws/providerconfig/v1alpha1"
)

const (
	// TagValueBastionRole describes the value associated with the role tag.
	TagValueBastionRole = "bastion"

	bastionUserData = `#!/bin/bash

BASTION_BOOTSTRAP_FILE=bastion_bootstrap.sh
BASTION_BOOTSTRAP=https://s3.amazonaws.com/aws-quickstart/quickstart-linux-bastion/scripts/bastion_bootstrap.sh

curl -s -o $BASTION_BOOTSTRAP_FILE $BASTION_BOOTSTRAP
chmod +x $BASTION_BOOTSTRAP_FILE

# This gets us far enough in the bastion script to be useful.
apt-get -y update && apt-get -y install python-pip
pip install --upgrade pip &> /dev/null

./$BASTION_BOOTSTRAP_FILE --banner https://${QSS3BucketName}.s3.amazonaws.com/${QSS3KeyPrefix}scripts/banner_message.txt --enable true
`
)

func (s *Service) ReconcileBastion(clusterName string, status *v1alpha1.AWSClusterProviderStatus) error {
	glog.V(2).Info("Reconciling bastion host")

	subnets := status.Network.Subnets
	if len(subnets.FilterPrivate()) == 0 {
		glog.V(2).Info("No private subnets available, skipping bastion host")
		return nil
	} else if len(subnets.FilterPublic()) == 0 {
		return errors.New("failed to reconcile bastion host, no public subnets are available")
	}

	spec := s.getDefaultBastion(clusterName, status.Region, status.Network)

	// Describe bastion instance, if any.
	instance, err := s.describeBastionInstance(clusterName, status)
	if IsNotFound(err) {
		instance, err = s.runInstance(spec)
		if err != nil {
			return err
		}

		glog.V(2).Infof("Created new bastion host: %+v", instance)

	} else if err != nil {
		return err
	}

	// TODO(vincepri): check for possible changes between the default spec and the instance.

	instance.DeepCopyInto(&status.Bastion)
	return nil
}

func (s *Service) describeBastionInstance(clusterName string, status *v1alpha1.AWSClusterProviderStatus) (*v1alpha1.Instance, error) {
	if status.Bastion.ID != "" {
		return s.InstanceIfExists(aws.String(status.Bastion.ID))
	}

	input := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String(fmt.Sprintf("tag:%s", TagNameAWSClusterAPIRole)),
				Values: []*string{aws.String(TagValueBastionRole)},
			},
		},
	}

	input.Filters = s.addTagFilters(clusterName, input.Filters)

	out, err := s.EC2.DescribeInstances(input)
	if err != nil {
		return nil, errors.Wrap(err, "failed to describe bastion host")
	}

	if len(out.Reservations) == 0 || len(out.Reservations[0].Instances) == 0 {
		return nil, NewNotFound(errors.New("bastion host not found"))
	}

	return fromSDKTypeToInstance(out.Reservations[0].Instances[0]), nil
}

func (s *Service) getDefaultBastion(clusterName string, region string, network v1alpha1.Network) *v1alpha1.Instance {
	i := &v1alpha1.Instance{
		Type:     "t2.micro",
		SubnetID: network.Subnets.FilterPublic()[0].ID,
		ImageID:  s.defaultBastionAMILookup(region),
		KeyName:  aws.String("default"),
		UserData: aws.String(base64.StdEncoding.EncodeToString([]byte(bastionUserData))),
		SecurityGroupIDs: []string{
			network.SecurityGroups[v1alpha1.SecurityGroupBastion].ID,
		},
		Tags: map[string]string{
			s.clusterTagKey(clusterName): string(ResourceLifecycleOwned),
			TagNameAWSClusterAPIRole:     TagValueBastionRole,
		},
	}

	return i
}
