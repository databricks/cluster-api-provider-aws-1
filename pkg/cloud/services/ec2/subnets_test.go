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

package ec2

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	infrav1 "sigs.k8s.io/cluster-api-provider-aws/api/v1alpha3"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/scope"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/services/ec2/mock_ec2iface"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/services/elb/mock_elbiface"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha3"
)

func init() {
	if err := clusterv1.AddToScheme(scheme.Scheme); err != nil {
		_ = fmt.Errorf("Error adding clusterv1 to scheme")
	}
}

const (
	subnetsVPCID = "vpc-subnets"
)

func TestReconcileSubnets(t *testing.T) {

	testCases := []struct {
		name          string
		input         *infrav1.NetworkSpec
		expect        func(m *mock_ec2iface.MockEC2APIMockRecorder)
		errorExpected bool
	}{
		{
			name: "Unmanaged VPC, 2 existing subnets in vpc, s subnet in spec, subnets match, should succeed",
			input: &infrav1.NetworkSpec{
				VPC: infrav1.VPCSpec{
					ID: subnetsVPCID,
				},
				Subnets: []*infrav1.SubnetSpec{
					{
						ID:               "subnet-1",
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.0.10.0/24",
						IsPublic:         true,
					},
					{
						ID:               "subnet-2",
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.0.20.0/24",
						IsPublic:         false,
					},
				},
			},
			expect: func(m *mock_ec2iface.MockEC2APIMockRecorder) {
				m.DescribeSubnets(gomock.Eq(&ec2.DescribeSubnetsInput{
					Filters: []*ec2.Filter{
						{
							Name:   aws.String("state"),
							Values: []*string{aws.String("pending"), aws.String("available")},
						},
						{
							Name:   aws.String("vpc-id"),
							Values: []*string{aws.String(subnetsVPCID)},
						},
					},
				})).
					Return(&ec2.DescribeSubnetsOutput{
						Subnets: []*ec2.Subnet{
							{
								VpcId:               aws.String(subnetsVPCID),
								SubnetId:            aws.String("subnet-1"),
								AvailabilityZone:    aws.String("us-east-1a"),
								CidrBlock:           aws.String("10.0.10.0/24"),
								MapPublicIpOnLaunch: aws.Bool(false),
							},
							{
								VpcId:               aws.String(subnetsVPCID),
								SubnetId:            aws.String("subnet-2"),
								AvailabilityZone:    aws.String("us-east-1a"),
								CidrBlock:           aws.String("10.0.20.0/24"),
								MapPublicIpOnLaunch: aws.Bool(false),
							},
						},
					}, nil)

				m.DescribeRouteTables(gomock.AssignableToTypeOf(&ec2.DescribeRouteTablesInput{})).
					Return(&ec2.DescribeRouteTablesOutput{}, nil)

				m.DescribeNatGatewaysPages(
					gomock.Eq(&ec2.DescribeNatGatewaysInput{
						Filter: []*ec2.Filter{
							{
								Name:   aws.String("vpc-id"),
								Values: []*string{aws.String(subnetsVPCID)},
							},
							{
								Name:   aws.String("state"),
								Values: []*string{aws.String("pending"), aws.String("available")},
							},
						},
					}),
					gomock.Any()).Return(nil)
			},
		},
		{
			name: "Unmanaged VPC, 2 existing subnet in vpc, 2 private subnet in spec, subnets don't match, should fail",
			input: &infrav1.NetworkSpec{
				VPC: infrav1.VPCSpec{
					ID: subnetsVPCID,
				},
				Subnets: []*infrav1.SubnetSpec{
					{
						ID:               "subnet-1",
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.0.10.0/24",
						IsPublic:         true,
					},
					{
						ID:               "subnet-2",
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.0.20.0/24",
						IsPublic:         false,
					},
				},
			},
			expect: func(m *mock_ec2iface.MockEC2APIMockRecorder) {
				m.DescribeSubnets(gomock.Eq(&ec2.DescribeSubnetsInput{
					Filters: []*ec2.Filter{
						{
							Name:   aws.String("state"),
							Values: []*string{aws.String("pending"), aws.String("available")},
						},
						{
							Name:   aws.String("vpc-id"),
							Values: []*string{aws.String(subnetsVPCID)},
						},
					},
				})).
					Return(&ec2.DescribeSubnetsOutput{
						Subnets: []*ec2.Subnet{
							{
								VpcId:               aws.String(subnetsVPCID),
								SubnetId:            aws.String("subnet-1"),
								AvailabilityZone:    aws.String("us-east-1a"),
								CidrBlock:           aws.String("10.0.10.0/24"),
								MapPublicIpOnLaunch: aws.Bool(false),
							},
							{
								VpcId:               aws.String(subnetsVPCID),
								SubnetId:            aws.String("subnet-3"),
								AvailabilityZone:    aws.String("us-east-1a"),
								CidrBlock:           aws.String("10.0.20.0/24"),
								MapPublicIpOnLaunch: aws.Bool(false),
							},
						},
					}, nil)

				m.DescribeRouteTables(gomock.AssignableToTypeOf(&ec2.DescribeRouteTablesInput{})).
					Return(&ec2.DescribeRouteTablesOutput{}, nil)

				m.DescribeNatGatewaysPages(
					gomock.Eq(&ec2.DescribeNatGatewaysInput{
						Filter: []*ec2.Filter{
							{
								Name:   aws.String("vpc-id"),
								Values: []*string{aws.String(subnetsVPCID)},
							},
							{
								Name:   aws.String("state"),
								Values: []*string{aws.String("pending"), aws.String("available")},
							},
						},
					}),
					gomock.Any()).Return(nil)
			},
			errorExpected: true,
		},
		{
			name: "Unmanaged VPC, 2 existing subnet2 in vpc, 0 subnet in spec, should fail",
			input: &infrav1.NetworkSpec{
				VPC: infrav1.VPCSpec{
					ID: subnetsVPCID,
				},
				Subnets: []*infrav1.SubnetSpec{},
			},
			expect: func(m *mock_ec2iface.MockEC2APIMockRecorder) {
				m.DescribeSubnets(gomock.Eq(&ec2.DescribeSubnetsInput{
					Filters: []*ec2.Filter{
						{
							Name:   aws.String("state"),
							Values: []*string{aws.String("pending"), aws.String("available")},
						},
						{
							Name:   aws.String("vpc-id"),
							Values: []*string{aws.String(subnetsVPCID)},
						},
					},
				})).
					Return(&ec2.DescribeSubnetsOutput{
						Subnets: []*ec2.Subnet{
							{
								VpcId:               aws.String(subnetsVPCID),
								SubnetId:            aws.String("subnet-1"),
								AvailabilityZone:    aws.String("us-east-1a"),
								CidrBlock:           aws.String("10.0.10.0/24"),
								MapPublicIpOnLaunch: aws.Bool(false),
							},
							{
								VpcId:               aws.String(subnetsVPCID),
								SubnetId:            aws.String("subnet-2"),
								AvailabilityZone:    aws.String("us-east-1a"),
								CidrBlock:           aws.String("10.0.20.0/24"),
								MapPublicIpOnLaunch: aws.Bool(false),
							},
						},
					}, nil)

				m.DescribeRouteTables(gomock.AssignableToTypeOf(&ec2.DescribeRouteTablesInput{})).
					Return(&ec2.DescribeRouteTablesOutput{}, nil)

				m.DescribeNatGatewaysPages(
					gomock.Eq(&ec2.DescribeNatGatewaysInput{
						Filter: []*ec2.Filter{
							{
								Name:   aws.String("vpc-id"),
								Values: []*string{aws.String(subnetsVPCID)},
							},
							{
								Name:   aws.String("state"),
								Values: []*string{aws.String("pending"), aws.String("available")},
							},
						},
					}),
					gomock.Any()).Return(nil)
			},
			errorExpected: true,
		},
		{
			name: "Unmanaged VPC, 0 existing subnets in vpc, 2 subnets in spec, should fail",
			input: &infrav1.NetworkSpec{
				VPC: infrav1.VPCSpec{
					ID: subnetsVPCID,
				},
				Subnets: []*infrav1.SubnetSpec{
					{
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.1.0.0/16",
						IsPublic:         false,
					},
					{
						AvailabilityZone: "us-east-1b",
						CidrBlock:        "10.2.0.0/16",
						IsPublic:         true,
					},
				},
			},
			expect: func(m *mock_ec2iface.MockEC2APIMockRecorder) {
				m.DescribeSubnets(gomock.Eq(&ec2.DescribeSubnetsInput{
					Filters: []*ec2.Filter{
						{
							Name:   aws.String("state"),
							Values: []*string{aws.String("pending"), aws.String("available")},
						},
						{
							Name:   aws.String("vpc-id"),
							Values: []*string{aws.String(subnetsVPCID)},
						},
					},
				})).
					Return(&ec2.DescribeSubnetsOutput{}, nil)

				m.DescribeRouteTables(gomock.AssignableToTypeOf(&ec2.DescribeRouteTablesInput{})).
					Return(&ec2.DescribeRouteTablesOutput{}, nil)

				m.DescribeNatGatewaysPages(
					gomock.Eq(&ec2.DescribeNatGatewaysInput{
						Filter: []*ec2.Filter{
							{
								Name:   aws.String("vpc-id"),
								Values: []*string{aws.String(subnetsVPCID)},
							},
							{
								Name:   aws.String("state"),
								Values: []*string{aws.String("pending"), aws.String("available")},
							},
						},
					}),
					gomock.Any()).Return(nil)
			},
			errorExpected: true,
		},
		{
			name: "Managed VPC, no subnets exist, 1 private and 1 public subnet in spec, create both",
			input: &infrav1.NetworkSpec{
				VPC: infrav1.VPCSpec{
					ID: subnetsVPCID,
					Tags: infrav1.Tags{
						infrav1.ClusterTagKey("test-cluster"): "owned",
					},
				},
				Subnets: []*infrav1.SubnetSpec{
					{
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.1.0.0/16",
						IsPublic:         false,
					},
					{
						AvailabilityZone: "us-east-1b",
						CidrBlock:        "10.2.0.0/16",
						IsPublic:         true,
					},
				},
			},
			expect: func(m *mock_ec2iface.MockEC2APIMockRecorder) {
				describeCall := m.DescribeSubnets(gomock.Eq(&ec2.DescribeSubnetsInput{
					Filters: []*ec2.Filter{
						{
							Name:   aws.String("state"),
							Values: []*string{aws.String("pending"), aws.String("available")},
						},
						{
							Name:   aws.String("vpc-id"),
							Values: []*string{aws.String(subnetsVPCID)},
						},
					},
				})).
					Return(&ec2.DescribeSubnetsOutput{}, nil)

				m.DescribeRouteTables(gomock.AssignableToTypeOf(&ec2.DescribeRouteTablesInput{})).
					Return(&ec2.DescribeRouteTablesOutput{}, nil)

				m.DescribeNatGatewaysPages(
					gomock.Eq(&ec2.DescribeNatGatewaysInput{
						Filter: []*ec2.Filter{
							{
								Name:   aws.String("vpc-id"),
								Values: []*string{aws.String(subnetsVPCID)},
							},
							{
								Name:   aws.String("state"),
								Values: []*string{aws.String("pending"), aws.String("available")},
							},
						},
					}),
					gomock.Any()).Return(nil)

				firstSubnet := m.CreateSubnet(gomock.Eq(&ec2.CreateSubnetInput{
					VpcId:            aws.String(subnetsVPCID),
					CidrBlock:        aws.String("10.1.0.0/16"),
					AvailabilityZone: aws.String("us-east-1a"),
				})).
					Return(&ec2.CreateSubnetOutput{
						Subnet: &ec2.Subnet{
							VpcId:               aws.String(subnetsVPCID),
							SubnetId:            aws.String("subnet-1"),
							CidrBlock:           aws.String("10.1.0.0/16"),
							AvailabilityZone:    aws.String("us-east-1a"),
							MapPublicIpOnLaunch: aws.Bool(false),
						},
					}, nil).
					After(describeCall)

				m.WaitUntilSubnetAvailable(gomock.Any()).
					After(firstSubnet)

				m.CreateTags(gomock.AssignableToTypeOf(&ec2.CreateTagsInput{})).
					Return(nil, nil)

				secondSubnet := m.CreateSubnet(gomock.Eq(&ec2.CreateSubnetInput{
					VpcId:            aws.String(subnetsVPCID),
					CidrBlock:        aws.String("10.2.0.0/16"),
					AvailabilityZone: aws.String("us-east-1b"),
				})).
					Return(&ec2.CreateSubnetOutput{
						Subnet: &ec2.Subnet{
							VpcId:               aws.String(subnetsVPCID),
							SubnetId:            aws.String("subnet-2"),
							CidrBlock:           aws.String("10.2.0.0/16"),
							AvailabilityZone:    aws.String("us-east-1a"),
							MapPublicIpOnLaunch: aws.Bool(false),
						},
					}, nil).
					After(firstSubnet)

				m.WaitUntilSubnetAvailable(gomock.Any()).
					After(secondSubnet)

				m.CreateTags(gomock.AssignableToTypeOf(&ec2.CreateTagsInput{}))

				m.ModifySubnetAttribute(&ec2.ModifySubnetAttributeInput{
					MapPublicIpOnLaunch: &ec2.AttributeBooleanValue{
						Value: aws.Bool(true),
					},
					SubnetId: aws.String("subnet-2"),
				}).
					Return(&ec2.ModifySubnetAttributeOutput{}, nil).
					After(secondSubnet)

			},
		},
		{
			name: "Managed VPC, no subnets exist, 1 private subnet in spec (no public subnet), should fail",
			input: &infrav1.NetworkSpec{
				VPC: infrav1.VPCSpec{
					ID: subnetsVPCID,
					Tags: infrav1.Tags{
						infrav1.ClusterTagKey("test-cluster"): "owned",
					},
				},
				Subnets: []*infrav1.SubnetSpec{
					{
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.1.0.0/16",
						IsPublic:         false,
					},
				},
			},
			expect: func(m *mock_ec2iface.MockEC2APIMockRecorder) {
				m.DescribeSubnets(gomock.Eq(&ec2.DescribeSubnetsInput{
					Filters: []*ec2.Filter{
						{
							Name:   aws.String("state"),
							Values: []*string{aws.String("pending"), aws.String("available")},
						},
						{
							Name:   aws.String("vpc-id"),
							Values: []*string{aws.String(subnetsVPCID)},
						},
					},
				})).
					Return(&ec2.DescribeSubnetsOutput{}, nil)

				m.DescribeRouteTables(gomock.AssignableToTypeOf(&ec2.DescribeRouteTablesInput{})).
					Return(&ec2.DescribeRouteTablesOutput{}, nil)

				m.DescribeNatGatewaysPages(
					gomock.Eq(&ec2.DescribeNatGatewaysInput{
						Filter: []*ec2.Filter{
							{
								Name:   aws.String("vpc-id"),
								Values: []*string{aws.String(subnetsVPCID)},
							},
							{
								Name:   aws.String("state"),
								Values: []*string{aws.String("pending"), aws.String("available")},
							},
						},
					}),
					gomock.Any()).Return(nil)
			},
			errorExpected: true,
		},
		{
			name: "Managed VPC, no existing subnets exist, one az, expect one private and one public from default",
			input: &infrav1.NetworkSpec{
				VPC: infrav1.VPCSpec{
					ID: subnetsVPCID,
					Tags: infrav1.Tags{
						infrav1.ClusterTagKey("test-cluster"): "owned",
					},
					CidrBlock: defaultVPCCidr,
				},
				Subnets: []*infrav1.SubnetSpec{},
			},
			expect: func(m *mock_ec2iface.MockEC2APIMockRecorder) {
				m.DescribeAvailabilityZones(gomock.Any()).
					Return(&ec2.DescribeAvailabilityZonesOutput{
						AvailabilityZones: []*ec2.AvailabilityZone{
							{
								ZoneName: aws.String("us-east-1c"),
							},
						},
					}, nil)

				describeCall := m.DescribeSubnets(gomock.Eq(&ec2.DescribeSubnetsInput{
					Filters: []*ec2.Filter{
						{
							Name:   aws.String("state"),
							Values: []*string{aws.String("pending"), aws.String("available")},
						},
						{
							Name:   aws.String("vpc-id"),
							Values: []*string{aws.String(subnetsVPCID)},
						},
					},
				})).
					Return(&ec2.DescribeSubnetsOutput{}, nil)

				m.DescribeRouteTables(gomock.AssignableToTypeOf(&ec2.DescribeRouteTablesInput{})).
					Return(&ec2.DescribeRouteTablesOutput{}, nil)

				m.DescribeNatGatewaysPages(
					gomock.Eq(&ec2.DescribeNatGatewaysInput{
						Filter: []*ec2.Filter{
							{
								Name:   aws.String("vpc-id"),
								Values: []*string{aws.String(subnetsVPCID)},
							},
							{
								Name:   aws.String("state"),
								Values: []*string{aws.String("pending"), aws.String("available")},
							},
						},
					}),
					gomock.Any()).Return(nil)

				firstSubnet := m.CreateSubnet(gomock.Eq(&ec2.CreateSubnetInput{
					VpcId:            aws.String(subnetsVPCID),
					CidrBlock:        aws.String("10.0.0.0/17"),
					AvailabilityZone: aws.String("us-east-1c"),
				})).
					Return(&ec2.CreateSubnetOutput{
						Subnet: &ec2.Subnet{
							VpcId:               aws.String(subnetsVPCID),
							SubnetId:            aws.String("subnet-1"),
							CidrBlock:           aws.String("10.0.0.0/17"),
							AvailabilityZone:    aws.String("us-east-1c"),
							MapPublicIpOnLaunch: aws.Bool(false),
						},
					}, nil).
					After(describeCall)

				m.WaitUntilSubnetAvailable(gomock.Any()).
					After(firstSubnet)

				m.CreateTags(gomock.AssignableToTypeOf(&ec2.CreateTagsInput{})).
					Return(nil, nil)

				m.ModifySubnetAttribute(&ec2.ModifySubnetAttributeInput{
					MapPublicIpOnLaunch: &ec2.AttributeBooleanValue{
						Value: aws.Bool(true),
					},
					SubnetId: aws.String("subnet-1"),
				}).
					Return(&ec2.ModifySubnetAttributeOutput{}, nil).
					After(firstSubnet)

				secondSubnet := m.CreateSubnet(gomock.Eq(&ec2.CreateSubnetInput{
					VpcId:            aws.String(subnetsVPCID),
					CidrBlock:        aws.String("10.0.128.0/17"),
					AvailabilityZone: aws.String("us-east-1c"),
				})).
					Return(&ec2.CreateSubnetOutput{
						Subnet: &ec2.Subnet{
							VpcId:               aws.String(subnetsVPCID),
							SubnetId:            aws.String("subnet-2"),
							CidrBlock:           aws.String("10.0.128.0/17"),
							AvailabilityZone:    aws.String("us-east-1c"),
							MapPublicIpOnLaunch: aws.Bool(false),
						},
					}, nil).
					After(firstSubnet)

				m.WaitUntilSubnetAvailable(gomock.Any()).
					After(secondSubnet)

				m.CreateTags(gomock.AssignableToTypeOf(&ec2.CreateTagsInput{}))

			},
		},
		{
			name: "Managed VPC, no existing subnets exist, two az's, expect two private and two public from default",
			input: &infrav1.NetworkSpec{
				VPC: infrav1.VPCSpec{
					ID: subnetsVPCID,
					Tags: infrav1.Tags{
						infrav1.ClusterTagKey("test-cluster"): "owned",
					},
					CidrBlock: defaultVPCCidr,
				},
				Subnets: []*infrav1.SubnetSpec{},
			},
			expect: func(m *mock_ec2iface.MockEC2APIMockRecorder) {
				m.DescribeAvailabilityZones(gomock.Any()).
					Return(&ec2.DescribeAvailabilityZonesOutput{
						AvailabilityZones: []*ec2.AvailabilityZone{
							{
								ZoneName: aws.String("us-east-1b"),
							},
							{
								ZoneName: aws.String("us-east-1c"),
							},
						},
					}, nil)

				describeCall := m.DescribeSubnets(gomock.Eq(&ec2.DescribeSubnetsInput{
					Filters: []*ec2.Filter{
						{
							Name:   aws.String("state"),
							Values: []*string{aws.String("pending"), aws.String("available")},
						},
						{
							Name:   aws.String("vpc-id"),
							Values: []*string{aws.String(subnetsVPCID)},
						},
					},
				})).
					Return(&ec2.DescribeSubnetsOutput{}, nil)

				m.DescribeRouteTables(gomock.AssignableToTypeOf(&ec2.DescribeRouteTablesInput{})).
					Return(&ec2.DescribeRouteTablesOutput{}, nil)

				m.DescribeNatGatewaysPages(
					gomock.Eq(&ec2.DescribeNatGatewaysInput{
						Filter: []*ec2.Filter{
							{
								Name:   aws.String("vpc-id"),
								Values: []*string{aws.String(subnetsVPCID)},
							},
							{
								Name:   aws.String("state"),
								Values: []*string{aws.String("pending"), aws.String("available")},
							},
						},
					}),
					gomock.Any()).Return(nil)

				zone1PublicSubnet := m.CreateSubnet(gomock.Eq(&ec2.CreateSubnetInput{
					VpcId:            aws.String(subnetsVPCID),
					CidrBlock:        aws.String("10.0.0.0/19"),
					AvailabilityZone: aws.String("us-east-1b"),
				})).
					Return(&ec2.CreateSubnetOutput{
						Subnet: &ec2.Subnet{
							VpcId:               aws.String(subnetsVPCID),
							SubnetId:            aws.String("subnet-1"),
							CidrBlock:           aws.String("10.0.0.0/19"),
							AvailabilityZone:    aws.String("us-east-1b"),
							MapPublicIpOnLaunch: aws.Bool(false),
						},
					}, nil).
					After(describeCall)

				m.WaitUntilSubnetAvailable(gomock.Any()).
					After(zone1PublicSubnet)

				m.CreateTags(gomock.AssignableToTypeOf(&ec2.CreateTagsInput{})).
					Return(nil, nil)

				m.ModifySubnetAttribute(&ec2.ModifySubnetAttributeInput{
					MapPublicIpOnLaunch: &ec2.AttributeBooleanValue{
						Value: aws.Bool(true),
					},
					SubnetId: aws.String("subnet-1"),
				}).
					Return(&ec2.ModifySubnetAttributeOutput{}, nil).
					After(zone1PublicSubnet)

				zone1PrivateSubnet := m.CreateSubnet(gomock.Eq(&ec2.CreateSubnetInput{
					VpcId:            aws.String(subnetsVPCID),
					CidrBlock:        aws.String("10.0.64.0/18"),
					AvailabilityZone: aws.String("us-east-1b"),
				})).
					Return(&ec2.CreateSubnetOutput{
						Subnet: &ec2.Subnet{
							VpcId:               aws.String(subnetsVPCID),
							SubnetId:            aws.String("subnet-2"),
							CidrBlock:           aws.String("10.0.64.0/18"),
							AvailabilityZone:    aws.String("us-east-1b"),
							MapPublicIpOnLaunch: aws.Bool(false),
						},
					}, nil).
					After(zone1PublicSubnet)

				m.WaitUntilSubnetAvailable(gomock.Any()).
					After(zone1PrivateSubnet)

				m.CreateTags(gomock.AssignableToTypeOf(&ec2.CreateTagsInput{}))

				// zone 2

				zone2PublicSubnet := m.CreateSubnet(gomock.Eq(&ec2.CreateSubnetInput{
					VpcId:            aws.String(subnetsVPCID),
					CidrBlock:        aws.String("10.0.32.0/19"),
					AvailabilityZone: aws.String("us-east-1c"),
				})).
					Return(&ec2.CreateSubnetOutput{
						Subnet: &ec2.Subnet{
							VpcId:               aws.String(subnetsVPCID),
							SubnetId:            aws.String("subnet-1"),
							CidrBlock:           aws.String("10.0.32.0/19"),
							AvailabilityZone:    aws.String("us-east-1c"),
							MapPublicIpOnLaunch: aws.Bool(false),
						},
					}, nil).
					After(zone1PrivateSubnet)

				m.WaitUntilSubnetAvailable(gomock.Any()).
					After(zone2PublicSubnet)

				m.CreateTags(gomock.AssignableToTypeOf(&ec2.CreateTagsInput{})).
					Return(nil, nil)

				m.ModifySubnetAttribute(&ec2.ModifySubnetAttributeInput{
					MapPublicIpOnLaunch: &ec2.AttributeBooleanValue{
						Value: aws.Bool(true),
					},
					SubnetId: aws.String("subnet-1"),
				}).
					Return(&ec2.ModifySubnetAttributeOutput{}, nil).
					After(zone2PublicSubnet)

				zone2PrivateSubnet := m.CreateSubnet(gomock.Eq(&ec2.CreateSubnetInput{
					VpcId:            aws.String(subnetsVPCID),
					CidrBlock:        aws.String("10.0.128.0/18"),
					AvailabilityZone: aws.String("us-east-1c"),
				})).
					Return(&ec2.CreateSubnetOutput{
						Subnet: &ec2.Subnet{
							VpcId:               aws.String(subnetsVPCID),
							SubnetId:            aws.String("subnet-2"),
							CidrBlock:           aws.String("10.0.128.0/18"),
							AvailabilityZone:    aws.String("us-east-1c"),
							MapPublicIpOnLaunch: aws.Bool(false),
						},
					}, nil).
					After(zone2PublicSubnet)

				m.WaitUntilSubnetAvailable(gomock.Any()).
					After(zone2PrivateSubnet)

				m.CreateTags(gomock.AssignableToTypeOf(&ec2.CreateTagsInput{}))

			},
		},
		{
			name: "Managed VPC, existing public subnet, 2 subnets in spec, should create 1 subnet",
			input: &infrav1.NetworkSpec{
				VPC: infrav1.VPCSpec{
					ID: subnetsVPCID,
					Tags: infrav1.Tags{
						infrav1.ClusterTagKey("test-cluster"): "owned",
					},
				},
				Subnets: []*infrav1.SubnetSpec{
					{
						ID:               "subnet-1",
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.0.0.0/17",
						IsPublic:         true,
					},
					{
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.0.128.0/17",
						IsPublic:         false,
					},
				},
			},
			expect: func(m *mock_ec2iface.MockEC2APIMockRecorder) {
				m.DescribeSubnets(gomock.Eq(&ec2.DescribeSubnetsInput{
					Filters: []*ec2.Filter{
						{
							Name:   aws.String("state"),
							Values: []*string{aws.String("pending"), aws.String("available")},
						},
						{
							Name:   aws.String("vpc-id"),
							Values: []*string{aws.String(subnetsVPCID)},
						},
					},
				})).
					Return(&ec2.DescribeSubnetsOutput{
						Subnets: []*ec2.Subnet{
							{
								VpcId:            aws.String(subnetsVPCID),
								SubnetId:         aws.String("subnet-1"),
								AvailabilityZone: aws.String("us-east-1a"),
								CidrBlock:        aws.String("10.0.0.0/17"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("sigs.k8s.io/cluster-api-provider-aws/cluster/test-cluster"),
										Value: aws.String("owned"),
									},
									{
										Key:   aws.String("sigs.k8s.io/cluster-api-provider-aws/role"),
										Value: aws.String("public"),
									},
									{
										Key:   aws.String("Name"),
										Value: aws.String("test-cluster-subnet-public"),
									},
									{
										Key:   aws.String("kubernetes.io/cluster/test-cluster"),
										Value: aws.String("shared"),
									},
								},
							},
						},
					}, nil)

				m.DescribeRouteTables(gomock.AssignableToTypeOf(&ec2.DescribeRouteTablesInput{})).
					Return(&ec2.DescribeRouteTablesOutput{}, nil)

				m.DescribeNatGatewaysPages(
					gomock.Eq(&ec2.DescribeNatGatewaysInput{
						Filter: []*ec2.Filter{
							{
								Name:   aws.String("vpc-id"),
								Values: []*string{aws.String(subnetsVPCID)},
							},
							{
								Name:   aws.String("state"),
								Values: []*string{aws.String("pending"), aws.String("available")},
							},
						},
					}),
					gomock.Any()).Return(nil)

				m.CreateSubnet(gomock.Eq(&ec2.CreateSubnetInput{
					VpcId:            aws.String(subnetsVPCID),
					CidrBlock:        aws.String("10.0.128.0/17"),
					AvailabilityZone: aws.String("us-east-1a"),
				})).
					Return(&ec2.CreateSubnetOutput{
						Subnet: &ec2.Subnet{
							VpcId:            aws.String(subnetsVPCID),
							SubnetId:         aws.String("subnet-2"),
							CidrBlock:        aws.String("10.0.128.0/17"),
							AvailabilityZone: aws.String("us-east-1a"),
						},
					}, nil)

				m.WaitUntilSubnetAvailable(gomock.Any())

				// Private subnet
				m.CreateTags(gomock.AssignableToTypeOf(&ec2.CreateTagsInput{})).
					Return(nil, nil)
				// Public subnet
				m.CreateTags(gomock.AssignableToTypeOf(&ec2.CreateTagsInput{})).
					Return(nil, nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			ec2Mock := mock_ec2iface.NewMockEC2API(mockCtrl)
			elbMock := mock_elbiface.NewMockELBAPI(mockCtrl)

			scope, err := scope.NewClusterScope(scope.ClusterScopeParams{
				Cluster: &clusterv1.Cluster{
					ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"},
				},
				AWSClients: scope.AWSClients{
					EC2: ec2Mock,
					ELB: elbMock,
				},
				AWSCluster: &infrav1.AWSCluster{
					Spec: infrav1.AWSClusterSpec{
						NetworkSpec: *tc.input,
					},
				},
			})
			if err != nil {
				t.Fatalf("Failed to create test context: %v", err)
			}

			tc.expect(ec2Mock.EXPECT())

			s := NewService(scope)
			err = s.reconcileSubnets()

			if tc.errorExpected && err == nil {
				t.Fatal("expected error reconciling but not no error")
			}
			if !tc.errorExpected && err != nil {
				t.Fatalf("got an unexpected error: %v", err)
			}
		})
	}
}

func TestDiscoverSubnets(t *testing.T) {
	testCases := []struct {
		name   string
		input  *infrav1.NetworkSpec
		mocks  func(m *mock_ec2iface.MockEC2APIMockRecorder)
		expect []*infrav1.SubnetSpec
	}{
		{
			name: "provided VPC finds internet routes",
			input: &infrav1.NetworkSpec{
				VPC: infrav1.VPCSpec{
					ID: subnetsVPCID,
				},
				Subnets: []*infrav1.SubnetSpec{
					{
						ID:               "subnet-1",
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.0.10.0/24",
						IsPublic:         true,
					},
					{
						ID:               "subnet-2",
						AvailabilityZone: "us-east-1a",
						CidrBlock:        "10.0.11.0/24",
						IsPublic:         false,
					},
				},
			},
			mocks: func(m *mock_ec2iface.MockEC2APIMockRecorder) {
				m.DescribeSubnets(gomock.Eq(&ec2.DescribeSubnetsInput{
					Filters: []*ec2.Filter{
						{
							Name:   aws.String("state"),
							Values: []*string{aws.String("pending"), aws.String("available")},
						},
						{
							Name:   aws.String("vpc-id"),
							Values: []*string{aws.String(subnetsVPCID)},
						},
					},
				})).
					Return(&ec2.DescribeSubnetsOutput{
						Subnets: []*ec2.Subnet{
							{
								VpcId:            aws.String(subnetsVPCID),
								SubnetId:         aws.String("subnet-1"),
								AvailabilityZone: aws.String("us-east-1a"),
								CidrBlock:        aws.String("10.0.10.0/24"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("Name"),
										Value: aws.String("provided-subnet-public"),
									},
								},
							},
							{
								VpcId:            aws.String(subnetsVPCID),
								SubnetId:         aws.String("subnet-2"),
								AvailabilityZone: aws.String("us-east-1a"),
								CidrBlock:        aws.String("10.0.11.0/24"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("Name"),
										Value: aws.String("provided-subnet-private"),
									},
								},
							},
						},
					}, nil)

				m.DescribeRouteTables(gomock.AssignableToTypeOf(&ec2.DescribeRouteTablesInput{})).
					Return(&ec2.DescribeRouteTablesOutput{
						RouteTables: []*ec2.RouteTable{
							{
								Associations: []*ec2.RouteTableAssociation{
									{
										SubnetId: aws.String("subnet-1"),
									},
								},
								Routes: []*ec2.Route{
									{
										DestinationCidrBlock: aws.String("10.0.10.0/24"),
										GatewayId:            aws.String("local"),
									},
									{
										DestinationCidrBlock: aws.String("0.0.0.0/0"),
										GatewayId:            aws.String("igw-0"),
									},
								},
								RouteTableId: aws.String("rtb-1"),
							},
							{
								Associations: []*ec2.RouteTableAssociation{
									{
										SubnetId: aws.String("subnet-2"),
									},
								},
								Routes: []*ec2.Route{
									{
										DestinationCidrBlock: aws.String("10.0.11.0/24"),
										GatewayId:            aws.String("local"),
									},
								},
								RouteTableId: aws.String("rtb-2"),
							},
						},
					}, nil)

				m.DescribeNatGatewaysPages(
					gomock.Eq(&ec2.DescribeNatGatewaysInput{
						Filter: []*ec2.Filter{
							{
								Name:   aws.String("vpc-id"),
								Values: []*string{aws.String(subnetsVPCID)},
							},
							{
								Name:   aws.String("state"),
								Values: []*string{aws.String("pending"), aws.String("available")},
							},
						},
					}),
					gomock.Any()).Return(nil)
			},
			expect: []*infrav1.SubnetSpec{
				{
					ID:               "subnet-1",
					AvailabilityZone: "us-east-1a",
					CidrBlock:        "10.0.10.0/24",
					IsPublic:         true,
					RouteTableID:     aws.String("rtb-1"),
					Tags: infrav1.Tags{
						"Name": "provided-subnet-public",
					},
				},
				{
					ID:               "subnet-2",
					AvailabilityZone: "us-east-1a",
					CidrBlock:        "10.0.11.0/24",
					IsPublic:         false,
					RouteTableID:     aws.String("rtb-2"),
					Tags: infrav1.Tags{
						"Name": "provided-subnet-private",
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			ec2Mock := mock_ec2iface.NewMockEC2API(mockCtrl)
			elbMock := mock_elbiface.NewMockELBAPI(mockCtrl)

			scope, err := scope.NewClusterScope(scope.ClusterScopeParams{
				Cluster: &clusterv1.Cluster{
					ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"},
				},
				AWSClients: scope.AWSClients{
					EC2: ec2Mock,
					ELB: elbMock,
				},
				AWSCluster: &infrav1.AWSCluster{
					Spec: infrav1.AWSClusterSpec{
						NetworkSpec: *tc.input,
					},
				},
			})
			if err != nil {
				t.Fatalf("Failed to create test context: %v", err)
			}

			tc.mocks(ec2Mock.EXPECT())

			s := NewService(scope)
			if err := s.reconcileSubnets(); err != nil {
				t.Fatalf("got an unexpected error: %v", err)
			}

			subnets := s.scope.AWSCluster.Spec.NetworkSpec.Subnets
			out := make(map[string]*infrav1.SubnetSpec)
			for _, sn := range subnets {
				out[sn.ID] = sn
			}
			for _, exp := range tc.expect {
				sn, ok := out[exp.ID]
				if !ok {
					t.Errorf("Expected to find subnet %s in %+v", exp.ID, subnets)
					continue
				}

				if !reflect.DeepEqual(sn, exp) {
					expected, _ := json.MarshalIndent(exp, "", "\t")
					actual, _ := json.MarshalIndent(sn, "", "\t")
					t.Errorf("Expected %s, got %s", string(expected), string(actual))
				}
				delete(out, exp.ID)
			}
			if len(out) > 0 {
				t.Errorf("Got unexpected subnets: %+v", out)
			}
		})
	}
}
