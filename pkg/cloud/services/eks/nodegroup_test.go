package eks

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/eks"
	. "github.com/onsi/gomega"
	expinfrav1 "sigs.k8s.io/cluster-api-provider-aws/exp/api/v1beta1"
	"testing"
)

// Implement unit test for getScalingConfigForDegradedNodeGroup function
func Test_getScalingConfigForDegradedNodeGroup(t *testing.T) {
	testCases := []struct {
		name      string
		ng        *eks.Nodegroup
		mp        expinfrav1.AWSManagedMachinePoolSpec
		expectMax int64
		expectMin int64
	}{
		{
			name:   "Nodegroup not in degraded state",
			ng:     &eks.Nodegroup{
				Status: aws.String(eks.NodegroupStatusActive),
				ScalingConfig: &eks.NodegroupScalingConfig{
					MaxSize: aws.Int64(10),
					MinSize: aws.Int64(1),
				},
			},
			mp:     expinfrav1.AWSManagedMachinePoolSpec{
				Scaling: &expinfrav1.ManagedMachinePoolScaling{
					MaxSize: aws.Int32(10),
					MinSize: aws.Int32(1),
				},
			},
			expectMax: 10,
			expectMin: 1,
		},
		{
			name: "Nodegroup in degraded state with an underlying issue that cannot be auto recovered",
			ng:     &eks.Nodegroup{
				Status: aws.String(eks.NodegroupStatusDegraded),
				Health: &eks.NodegroupHealth{
					Issues: []*eks.Issue{
						{
							Code: aws.String("AsgInstanceLaunchFailures"),
							Message: aws.String("Could not launch On-Demand Instances. InvalidAMIID.NotFound - The image id '[ami-02c7e84c65fcfecee]' does not exist. Launching EC2 instance failed."),
						},
					},
				},
				ScalingConfig: &eks.NodegroupScalingConfig{
					MaxSize: aws.Int64(10),
					MinSize: aws.Int64(1),
				},
			},
			mp:     expinfrav1.AWSManagedMachinePoolSpec{
				Scaling: &expinfrav1.ManagedMachinePoolScaling{
					MaxSize: aws.Int32(10),
					MinSize: aws.Int32(1),
				},
			},
			expectMax: 10,
			expectMin: 1,
		},
		{
			name: "Nodegroup in degraded state, desired size and current size are already different",
			ng:     &eks.Nodegroup{
				Status: aws.String(eks.NodegroupStatusDegraded),
				Health: &eks.NodegroupHealth{
					Issues: []*eks.Issue{
						{
							Code: aws.String("AsgInstanceLaunchFailures"),
							Message: aws.String("Could not launch On-Demand Instances. InsufficientInstanceCapacity - We currently do not have sufficient g5.12xlarge capacity in the Availability Zone you requested (us-east-1b). Our system will be working on provisioning additional capacity. You can currently get g5.12xlarge capacity by not specifying an Availability Zone in your request or choosing us-east-1a, us-east-1c, us-east-1d, us-east-1f. Launching EC2 instance failed."),
						},
					},
				},
				ScalingConfig: &eks.NodegroupScalingConfig{
					MaxSize: aws.Int64(10),
					MinSize: aws.Int64(0),
				},
			},
			mp:     expinfrav1.AWSManagedMachinePoolSpec{
				Scaling: &expinfrav1.ManagedMachinePoolScaling{
					MaxSize: aws.Int32(10),
					MinSize: aws.Int32(1),
				},
			},
			expectMax: 10,
			expectMin: 1,
		},
		{
			name: "Nodegroup in degraded state, desired min size is equal to desired max size",
			ng:     &eks.Nodegroup{
				Status: aws.String(eks.NodegroupStatusDegraded),
				Health: &eks.NodegroupHealth{
					Issues: []*eks.Issue{
						{
							Code: aws.String("AsgInstanceLaunchFailures"),
							Message: aws.String("Could not launch On-Demand Instances. InsufficientInstanceCapacity - We currently do not have sufficient g5.12xlarge capacity in the Availability Zone you requested (us-east-1b). Our system will be working on provisioning additional capacity. You can currently get g5.12xlarge capacity by not specifying an Availability Zone in your request or choosing us-east-1a, us-east-1c, us-east-1d, us-east-1f. Launching EC2 instance failed."),
						},
					},
				},
				ScalingConfig: &eks.NodegroupScalingConfig{
					MaxSize: aws.Int64(5),
					MinSize: aws.Int64(5),
				},
			},
			mp:     expinfrav1.AWSManagedMachinePoolSpec{
				Scaling: &expinfrav1.ManagedMachinePoolScaling{
					MaxSize: aws.Int32(5),
					MinSize: aws.Int32(5),
				},
			},
			expectMax: 5,
			expectMin: 4,
		},
		{
			name: "Nodegroup in degraded state, desired min size > 0",
			ng:     &eks.Nodegroup{
				Status: aws.String(eks.NodegroupStatusDegraded),
				Health: &eks.NodegroupHealth{
					Issues: []*eks.Issue{
						{
							Code: aws.String("AsgInstanceLaunchFailures"),
							Message: aws.String("Could not launch On-Demand Instances. InsufficientInstanceCapacity - We currently do not have sufficient g5.12xlarge capacity in the Availability Zone you requested (us-east-1b). Our system will be working on provisioning additional capacity. You can currently get g5.12xlarge capacity by not specifying an Availability Zone in your request or choosing us-east-1a, us-east-1c, us-east-1d, us-east-1f. Launching EC2 instance failed."),
						},
					},
				},
				ScalingConfig: &eks.NodegroupScalingConfig{
					MaxSize: aws.Int64(10),
					MinSize: aws.Int64(1),
				},
			},
			mp:     expinfrav1.AWSManagedMachinePoolSpec{
				Scaling: &expinfrav1.ManagedMachinePoolScaling{
					MaxSize: aws.Int32(10),
					MinSize: aws.Int32(1),
				},
			},
			expectMax: 10,
			expectMin: 0,
		},
		{
			name: "Nodegroup in degraded state, desired min size == 0",
			ng:     &eks.Nodegroup{
				Status: aws.String(eks.NodegroupStatusDegraded),
				Health: &eks.NodegroupHealth{
					Issues: []*eks.Issue{
						{
							Code: aws.String("AsgInstanceLaunchFailures"),
							Message: aws.String("Could not launch On-Demand Instances. InsufficientInstanceCapacity - We currently do not have sufficient g5.12xlarge capacity in the Availability Zone you requested (us-east-1b). Our system will be working on provisioning additional capacity. You can currently get g5.12xlarge capacity by not specifying an Availability Zone in your request or choosing us-east-1a, us-east-1c, us-east-1d, us-east-1f. Launching EC2 instance failed."),
						},
					},
				},
				ScalingConfig: &eks.NodegroupScalingConfig{
					MaxSize: aws.Int64(10),
					MinSize: aws.Int64(0),
				},
			},
			mp:     expinfrav1.AWSManagedMachinePoolSpec{
				Scaling: &expinfrav1.ManagedMachinePoolScaling{
					MaxSize: aws.Int32(10),
					MinSize: aws.Int32(0),
				},
			},
			expectMax: 10,
			expectMin: 1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			max, min := getScalingConfigForDegradedNodeGroup(tc.ng, tc.mp)
			g.Expect(max).To(Equal(tc.expectMax))
			g.Expect(min).To(Equal(tc.expectMin))
		})
	}
}