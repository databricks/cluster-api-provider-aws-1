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

package cluster_test

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/elb/elbiface"
	"github.com/golang/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	providerconfig "sigs.k8s.io/cluster-api-provider-aws/cloud/aws/providerconfig/v1alpha1"
	clusterv1 "sigs.k8s.io/cluster-api/pkg/apis/cluster/v1alpha1"
	clientv1 "sigs.k8s.io/cluster-api/pkg/client/clientset_generated/clientset/typed/cluster/v1alpha1"

	"sigs.k8s.io/cluster-api-provider-aws/cloud/aws/actuators/cluster"
	"sigs.k8s.io/cluster-api-provider-aws/cloud/aws/actuators/cluster/mock_clusteriface"
	"sigs.k8s.io/cluster-api-provider-aws/cloud/aws/services/ec2/mock_ec2iface"
	"sigs.k8s.io/cluster-api-provider-aws/cloud/aws/services/elb/mock_elbiface"
)

type clusterGetter struct {
	ci *mock_clusteriface.MockClusterInterface
}

func (c *clusterGetter) Clusters(ns string) clientv1.ClusterInterface {
	return c.ci
}

type ec2Getter struct {
	ec2 *mock_ec2iface.MockEC2API
}

func (d *ec2Getter) EC2(clusterConfig *providerconfig.AWSClusterProviderConfig) ec2iface.EC2API {
	return d.ec2
}

type elbGetter struct {
	elb *mock_elbiface.MockELBAPI
}

func (d *elbGetter) ELB(clusterConfig *providerconfig.AWSClusterProviderConfig) elbiface.ELBAPI {
	return d.elb
}

func TestReconcile(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cg := &clusterGetter{
		ci: mock_clusteriface.NewMockClusterInterface(mockCtrl),
	}

	mEC2 := mock_ec2iface.NewMockEC2API(mockCtrl)
	mELB := mock_elbiface.NewMockELBAPI(mockCtrl)
	defer mockCtrl.Finish()

	cg.ci.EXPECT().
		UpdateStatus(gomock.AssignableToTypeOf(&clusterv1.Cluster{})).
		Return(&clusterv1.Cluster{}, nil)

	gomock.InOrder(
		mEC2.EXPECT().
			DescribeVpcs(&ec2.DescribeVpcsInput{
				Filters: []*ec2.Filter{&ec2.Filter{
					Name:   aws.String("tag-key"),
					Values: aws.StringSlice([]string{"kubernetes.io/cluster/test"}),
				}},
			}).
			Return(&ec2.DescribeVpcsOutput{
				Vpcs: []*ec2.Vpc{},
			}, nil),
		mEC2.EXPECT().
			CreateVpc(&ec2.CreateVpcInput{
				CidrBlock: aws.String("10.0.0.0/16"),
			}).
			Return(&ec2.CreateVpcOutput{
				Vpc: &ec2.Vpc{
					VpcId:     aws.String("1234"),
					CidrBlock: aws.String("10.0.0.0/16"),
				},
			}, nil),
		mEC2.EXPECT().
			WaitUntilVpcAvailable(&ec2.DescribeVpcsInput{
				VpcIds: []*string{aws.String("1234")},
			}).
			Return(nil),
		mEC2.EXPECT().
			CreateTags(&ec2.CreateTagsInput{
				Resources: aws.StringSlice([]string{"1234"}),
				Tags: []*ec2.Tag{&ec2.Tag{
					Key:   aws.String("kubernetes.io/cluster/test"),
					Value: aws.String("owned"),
				}},
			}).
			Return(nil, nil),
		mEC2.EXPECT().
			DescribeSubnets(&ec2.DescribeSubnetsInput{
				Filters: []*ec2.Filter{
					&ec2.Filter{
						Name: aws.String("vpc-id"),
						Values: []*string{
							aws.String("1234"),
						},
					},
					&ec2.Filter{
						Name:   aws.String("tag-key"),
						Values: []*string{aws.String("kubernetes.io/cluster/test")},
					},
				},
			}).
			Return(&ec2.DescribeSubnetsOutput{
				Subnets: []*ec2.Subnet{
					&ec2.Subnet{
						SubnetId:            aws.String("snow"),
						VpcId:               aws.String("1234"),
						AvailabilityZone:    aws.String("antarctica"),
						CidrBlock:           aws.String("10.0.0.0/24"),
						MapPublicIpOnLaunch: aws.Bool(false),
					},
					&ec2.Subnet{
						SubnetId:            aws.String("ice"),
						VpcId:               aws.String("1234"),
						AvailabilityZone:    aws.String("antarctica"),
						CidrBlock:           aws.String("10.0.1.0/24"),
						MapPublicIpOnLaunch: aws.Bool(true),
					},
				},
			}, nil),
		mEC2.EXPECT().
			DescribeAvailabilityZones(&ec2.DescribeAvailabilityZonesInput{
				Filters: []*ec2.Filter{
					&ec2.Filter{
						Name:   aws.String("state"),
						Values: []*string{aws.String("available")},
					},
				},
			}).
			Return(&ec2.DescribeAvailabilityZonesOutput{
				AvailabilityZones: []*ec2.AvailabilityZone{
					&ec2.AvailabilityZone{ZoneName: aws.String("antarctica")},
				},
			}, nil),
		mEC2.EXPECT().
			DescribeInternetGateways(&ec2.DescribeInternetGatewaysInput{
				Filters: []*ec2.Filter{
					&ec2.Filter{
						Name:   aws.String("attachment.vpc-id"),
						Values: []*string{aws.String("1234")},
					},
					&ec2.Filter{
						Name:   aws.String("tag-key"),
						Values: []*string{aws.String("kubernetes.io/cluster/test")},
					},
				},
			}).
			Return(&ec2.DescribeInternetGatewaysOutput{
				InternetGateways: []*ec2.InternetGateway{
					&ec2.InternetGateway{
						InternetGatewayId: aws.String("carrot"),
					},
				},
			}, nil),
		mEC2.EXPECT().
			DescribeNatGatewaysPages(gomock.Any(), gomock.Any()).
			Return(nil),
		mEC2.EXPECT().
			AllocateAddress(&ec2.AllocateAddressInput{Domain: aws.String("vpc")}).
			Return(&ec2.AllocateAddressOutput{AllocationId: aws.String("scarf")}, nil),
		mEC2.EXPECT().
			CreateTags(&ec2.CreateTagsInput{
				Resources: aws.StringSlice([]string{"scarf"}),
				Tags: []*ec2.Tag{&ec2.Tag{
					Key:   aws.String("kubernetes.io/cluster/test"),
					Value: aws.String("owned"),
				}},
			}).
			Return(nil, nil),
		mEC2.EXPECT().
			CreateNatGateway(&ec2.CreateNatGatewayInput{
				AllocationId: aws.String("scarf"),
				SubnetId:     aws.String("ice"),
			}).
			Return(&ec2.CreateNatGatewayOutput{
				NatGateway: &ec2.NatGateway{
					NatGatewayId: aws.String("nat-ice1"),
				},
			}, nil),
		mEC2.EXPECT().
			WaitUntilNatGatewayAvailable(&ec2.DescribeNatGatewaysInput{NatGatewayIds: []*string{aws.String("nat-ice1")}}).
			Return(nil),
		mEC2.EXPECT().
			CreateTags(&ec2.CreateTagsInput{
				Resources: aws.StringSlice([]string{"nat-ice1"}),
				Tags: []*ec2.Tag{&ec2.Tag{
					Key:   aws.String("kubernetes.io/cluster/test"),
					Value: aws.String("owned"),
				}},
			}).
			Return(nil, nil),
		mEC2.EXPECT().
			DescribeRouteTables(&ec2.DescribeRouteTablesInput{
				Filters: []*ec2.Filter{
					&ec2.Filter{
						Name: aws.String("vpc-id"),
						Values: []*string{
							aws.String("1234"),
						},
					},
					&ec2.Filter{
						Name:   aws.String("tag-key"),
						Values: []*string{aws.String("kubernetes.io/cluster/test")},
					},
				},
			}).Return(&ec2.DescribeRouteTablesOutput{}, nil),
		mEC2.EXPECT().
			CreateRouteTable(&ec2.CreateRouteTableInput{VpcId: aws.String("1234")}).
			Return(&ec2.CreateRouteTableOutput{RouteTable: &ec2.RouteTable{RouteTableId: aws.String("rt-1")}}, nil),
		mEC2.EXPECT().
			CreateTags(&ec2.CreateTagsInput{
				Resources: aws.StringSlice([]string{"rt-1"}),
				Tags: []*ec2.Tag{&ec2.Tag{
					Key:   aws.String("kubernetes.io/cluster/test"),
					Value: aws.String("owned"),
				}},
			}).
			Return(nil, nil),
		mEC2.EXPECT().
			CreateRoute(&ec2.CreateRouteInput{
				RouteTableId:         aws.String("rt-1"),
				DestinationCidrBlock: aws.String("0.0.0.0/0"),
				NatGatewayId:         aws.String("nat-ice1"),
			}).
			Return(&ec2.CreateRouteOutput{}, nil),
		mEC2.EXPECT().
			AssociateRouteTable(&ec2.AssociateRouteTableInput{RouteTableId: aws.String("rt-1"), SubnetId: aws.String("snow")}).
			Return(&ec2.AssociateRouteTableOutput{}, nil),
		mEC2.EXPECT().
			CreateRouteTable(&ec2.CreateRouteTableInput{VpcId: aws.String("1234")}).
			Return(&ec2.CreateRouteTableOutput{RouteTable: &ec2.RouteTable{RouteTableId: aws.String("rt-2")}}, nil),
		mEC2.EXPECT().
			CreateTags(&ec2.CreateTagsInput{
				Resources: aws.StringSlice([]string{"rt-2"}),
				Tags: []*ec2.Tag{&ec2.Tag{
					Key:   aws.String("kubernetes.io/cluster/test"),
					Value: aws.String("owned"),
				}},
			}).
			Return(nil, nil),
		mEC2.EXPECT().
			CreateRoute(&ec2.CreateRouteInput{
				RouteTableId:         aws.String("rt-2"),
				DestinationCidrBlock: aws.String("0.0.0.0/0"),
				GatewayId:            aws.String("carrot"),
			}).
			Return(&ec2.CreateRouteOutput{}, nil),
		mEC2.EXPECT().
			AssociateRouteTable(&ec2.AssociateRouteTableInput{RouteTableId: aws.String("rt-2"), SubnetId: aws.String("ice")}).
			Return(&ec2.AssociateRouteTableOutput{}, nil),
		mEC2.EXPECT().
			DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
				Filters: []*ec2.Filter{
					{
						Name:   aws.String("vpc-id"),
						Values: []*string{aws.String("1234")},
					},
					{
						Name:   aws.String("tag-key"),
						Values: []*string{aws.String("kubernetes.io/cluster/test")},
					},
				},
			}).
			Return(&ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []*ec2.SecurityGroup{
					&ec2.SecurityGroup{
						GroupId:   aws.String("sg-bastion1"),
						GroupName: aws.String("test-bastion"),
						IpPermissions: []*ec2.IpPermission{
							&ec2.IpPermission{
								FromPort:   aws.Int64(22),
								ToPort:     aws.Int64(22),
								IpProtocol: aws.String("tcp"),
								IpRanges: []*ec2.IpRange{
									&ec2.IpRange{
										CidrIp:      aws.String("0.0.0.0/0"),
										Description: aws.String("SSH"),
									},
								},
							},
						},
					},
					&ec2.SecurityGroup{
						GroupId:   aws.String("sg-cp1"),
						GroupName: aws.String("test-controlplane"),
						IpPermissions: []*ec2.IpPermission{
							&ec2.IpPermission{
								FromPort:   aws.Int64(22),
								ToPort:     aws.Int64(22),
								IpProtocol: aws.String("tcp"),
								UserIdGroupPairs: []*ec2.UserIdGroupPair{
									&ec2.UserIdGroupPair{
										GroupId:     aws.String("sg-bastion1"),
										Description: aws.String("SSH"),
									},
								},
							},
							&ec2.IpPermission{
								FromPort:   aws.Int64(6443),
								ToPort:     aws.Int64(6443),
								IpProtocol: aws.String("tcp"),
								IpRanges: []*ec2.IpRange{
									&ec2.IpRange{
										CidrIp:      aws.String("0.0.0.0/0"),
										Description: aws.String("Kubernetes API"),
									},
								},
							},
							&ec2.IpPermission{
								FromPort:   aws.Int64(2379),
								ToPort:     aws.Int64(2379),
								IpProtocol: aws.String("tcp"),
								UserIdGroupPairs: []*ec2.UserIdGroupPair{
									&ec2.UserIdGroupPair{
										GroupId:     aws.String("sg-cp1"),
										Description: aws.String("etcd"),
									},
								},
							},
							&ec2.IpPermission{
								FromPort:   aws.Int64(2380),
								ToPort:     aws.Int64(2380),
								IpProtocol: aws.String("tcp"),
								UserIdGroupPairs: []*ec2.UserIdGroupPair{
									&ec2.UserIdGroupPair{
										GroupId:     aws.String("sg-cp1"),
										Description: aws.String("etcd peer"),
									},
								},
							},
						},
					},
					&ec2.SecurityGroup{
						GroupId:   aws.String("sg-nd1"),
						GroupName: aws.String("test-node"),
						IpPermissions: []*ec2.IpPermission{
							&ec2.IpPermission{
								FromPort:   aws.Int64(22),
								ToPort:     aws.Int64(22),
								IpProtocol: aws.String("tcp"),
								UserIdGroupPairs: []*ec2.UserIdGroupPair{
									&ec2.UserIdGroupPair{
										GroupId:     aws.String("sg-bastion1"),
										Description: aws.String("SSH"),
									},
								},
							},
							&ec2.IpPermission{
								FromPort:   aws.Int64(30000),
								ToPort:     aws.Int64(32767),
								IpProtocol: aws.String("tcp"),
								IpRanges: []*ec2.IpRange{
									&ec2.IpRange{
										CidrIp:      aws.String("0.0.0.0/0"),
										Description: aws.String("Node Port Services"),
									},
								},
							},
							&ec2.IpPermission{
								FromPort:   aws.Int64(10250),
								ToPort:     aws.Int64(10250),
								IpProtocol: aws.String("tcp"),
								UserIdGroupPairs: []*ec2.UserIdGroupPair{
									&ec2.UserIdGroupPair{
										GroupId:     aws.String("sg-cp1"),
										Description: aws.String("Kubelet API"),
									},
								},
							},
						},
					},
				},
			}, nil),

		// Reconcile bastion.
		mEC2.EXPECT().
			DescribeInstances(gomock.Eq(&ec2.DescribeInstancesInput{
				Filters: []*ec2.Filter{
					&ec2.Filter{
						Name:   aws.String("tag:sigs.k8s.io/cluster-api-provider-aws/role"),
						Values: []*string{aws.String("bastion")},
					},
					&ec2.Filter{
						Name:   aws.String("tag-key"),
						Values: []*string{aws.String("kubernetes.io/cluster/test")},
					},
				},
			})).
			Return(&ec2.DescribeInstancesOutput{}, nil),
		mEC2.EXPECT().
			RunInstances(gomock.AssignableToTypeOf(&ec2.RunInstancesInput{})).
			DoAndReturn(func(input *ec2.RunInstancesInput) (*ec2.Reservation, error) {
				if len(input.TagSpecifications) == 0 {
					t.Fatalf("expected tags to be applied on bootstrap, got none")
				}

				if input.TagSpecifications[0].ResourceType == nil || *input.TagSpecifications[0].ResourceType != ec2.ResourceTypeInstance {
					t.Fatalf("expected tag specification to be instance, got %v", input.TagSpecifications[0].ResourceType)
				}

				if len(input.TagSpecifications[0].Tags) < 2 {
					t.Fatalf("was expecting at least 2 tags for bastion host got: %v", input.TagSpecifications[0].Tags)
				}

				for _, key := range []string{"sigs.k8s.io/cluster-api-provider-aws/role", "kubernetes.io/cluster/test"} {
					found := false
					for _, x := range input.TagSpecifications[0].Tags {
						if *x.Key == key {
							found = true
							break
						}
					}

					if !found {
						t.Fatalf("couldn't find tag for bastion host: %s", key)
					}
				}

				return &ec2.Reservation{
					Instances: []*ec2.Instance{
						&ec2.Instance{
							State:        &ec2.InstanceState{Code: aws.Int64(0), Name: aws.String("pending")},
							InstanceId:   aws.String("bastion-1"),
							InstanceType: input.InstanceType,
							ImageId:      input.ImageId,
							SubnetId:     input.SubnetId,
						},
					},
				}, nil
			}),

		// Reconcile load balancers.
		mELB.EXPECT().
			DescribeLoadBalancers(&elb.DescribeLoadBalancersInput{LoadBalancerNames: []*string{aws.String("test-apiserver")}}).
			Return(&elb.DescribeLoadBalancersOutput{}, nil),
		mELB.EXPECT().
			CreateLoadBalancer(gomock.Eq(&elb.CreateLoadBalancerInput{
				LoadBalancerName: aws.String("test-apiserver"),
				Scheme:           aws.String("Internet-facing"),
				Subnets:          []*string{aws.String("snow")},
				SecurityGroups:   []*string{aws.String("sg-cp1")},
				Listeners: []*elb.Listener{
					&elb.Listener{
						LoadBalancerPort: aws.Int64(6443),
						Protocol:         aws.String("TCP"),
						InstancePort:     aws.Int64(6443),
						InstanceProtocol: aws.String("TCP"),
					},
				},
				Tags: []*elb.Tag{
					&elb.Tag{
						Key:   aws.String("sigs.k8s.io/cluster-api-provider-aws/role"),
						Value: aws.String("apiserver"),
					},
					&elb.Tag{
						Key:   aws.String("kubernetes.io/cluster/test"),
						Value: aws.String("owned"),
					},
				},
			})).
			Return(&elb.CreateLoadBalancerOutput{DNSName: aws.String("apiserver.loadbalancer.kubernetes.io")}, nil),
		mELB.EXPECT().
			ConfigureHealthCheck(gomock.Any()).Return(&elb.ConfigureHealthCheckOutput{}, nil),
	)

	c, err := providerconfig.NewCodec()
	if err != nil {
		t.Fatalf("failed to create codec: %v", err)
	}
	ap := cluster.ActuatorParams{
		Codec:          c,
		ClustersGetter: cg,
		EC2Getter:      &ec2Getter{ec2: mEC2},
		ELBGetter:      &elbGetter{elb: mELB},
	}

	a, err := cluster.NewActuator(ap)
	if err != nil {
		t.Fatalf("could not create an actuator: %v", err)
	}

	cluster := &clusterv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{Name: "test", ClusterName: "test"},
		Spec: clusterv1.ClusterSpec{
			ProviderConfig: clusterv1.ProviderConfig{
				Value: &runtime.RawExtension{
					Raw: []byte(`{"kind":"AWSClusterProviderConfig","apiVersion":"awsproviderconfig/v1alpha1","region":"us-east-1"}`),
				},
			},
		},
	}

	if err := a.Reconcile(cluster); err != nil {
		t.Fatalf("failed to reconcile cluster: %v", err)
	}
}
