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

package machine

// should not need to import the ec2 sdk here
import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/apis/awsprovider/v1alpha1"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/aws/actuators"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/aws/services"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/aws/services/awserrors"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/deployer"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/tokens"
	clusterv1 "sigs.k8s.io/cluster-api/pkg/apis/cluster/v1alpha1"
	client "sigs.k8s.io/cluster-api/pkg/client/clientset_generated/clientset/typed/cluster/v1alpha1"
	controllerError "sigs.k8s.io/cluster-api/pkg/controller/error"
)

// Actuator is responsible for performing machine reconciliation.
type Actuator struct {
	*deployer.Deployer

	client client.ClusterV1alpha1Interface
}

// ActuatorParams holds parameter information for Actuator.
type ActuatorParams struct {
	Client client.ClusterV1alpha1Interface
}

// NewActuator returns an actuator.
func NewActuator(params ActuatorParams) *Actuator {
	res := &Actuator{
		client: params.Client,
	}

	res.Deployer = deployer.New(services.NewSDKGetter())
	return res
}

// Create creates a machine and is invoked by the machine controller.
func (a *Actuator) Create(cluster *clusterv1.Cluster, machine *clusterv1.Machine) error {
	klog.Infof("Creating machine %v for cluster %v", machine.Name, cluster.Name)

	scope, err := actuators.NewMachineScope(actuators.MachineScopeParams{Machine: machine, Cluster: cluster, Client: a.client})
	if err != nil {
		return err
	}

	defer scope.Close()

	controlPlaneURL, err := a.GetIP(cluster, nil)
	if err != nil {
		return errors.Wrap(err, "failed to retrieve controlplane url during machine creation")
	}

	var bootstrapToken string
	if machine.ObjectMeta.Labels["set"] == "node" {
		kubeConfig, err := a.GetKubeConfig(cluster, nil)
		if err != nil {
			return errors.Wrap(err, "failed to retrieve kubeconfig during machine creation")
		}

		clientConfig, err := clientcmd.BuildConfigFromKubeconfigGetter(controlPlaneURL, func() (*clientcmdapi.Config, error) {
			return clientcmd.Load([]byte(kubeConfig))
		})

		if err != nil {
			return errors.Wrap(err, "failed to retrieve kubeconfig during machine creation")
		}

		coreClient, err := corev1.NewForConfig(clientConfig)
		if err != nil {
			return errors.Wrap(err, "failed to initialize new corev1 client")
		}

		bootstrapToken, err = tokens.NewBootstrap(coreClient, 10*time.Minute)
		if err != nil {
			return errors.Wrap(err, "failed to create new bootstrap token")
		}
	}

	i, err := scope.EC2.CreateOrGetMachine(machine, scope.MachineStatus, scope.MachineConfig, scope.ClusterStatus, scope.ClusterConfig, cluster, bootstrapToken)
	if err != nil {
		if awserrors.IsFailedDependency(errors.Cause(err)) {
			klog.Errorf("network not ready to launch instances yet: %s", err)
			return &controllerError.RequeueAfterError{
				RequeueAfter: time.Minute,
			}
		}

		return errors.Wrap(err, "failed to create or get machine")
	}

	scope.MachineStatus.InstanceID = &i.ID
	scope.MachineStatus.InstanceState = aws.String(string(i.State))

	if machine.Annotations == nil {
		machine.Annotations = map[string]string{}
	}

	machine.Annotations["cluster-api-provider-aws"] = "true"

	if err := a.reconcileLBAttachment(scope, machine, i); err != nil {
		return errors.Wrap(err, "failed to reconcile LB attachment")
	}

	return nil
}

func (a *Actuator) reconcileLBAttachment(scope *actuators.MachineScope, m *clusterv1.Machine, i *v1alpha1.Instance) error {
	if m.ObjectMeta.Labels["set"] == "controlplane" {
		if err := scope.ELB.RegisterInstanceWithAPIServerELB(scope.ClusterConfig.Name, i.ID); err != nil {
			return errors.Wrapf(err, "could not register control plane instance %q with load balancer", i.ID)
		}
	}

	return nil
}

// Delete deletes a machine and is invoked by the Machine Controller
func (a *Actuator) Delete(cluster *clusterv1.Cluster, machine *clusterv1.Machine) error {
	klog.Infof("Deleting machine %v for cluster %v.", machine.Name, cluster.Name)

	scope, err := actuators.NewMachineScope(actuators.MachineScopeParams{Machine: machine, Cluster: cluster, Client: a.client})
	if err != nil {
		return err
	}

	defer scope.Close()

	instance, err := scope.EC2.InstanceIfExists(scope.MachineStatus.InstanceID)
	if err != nil {
		return errors.Wrap(err, "failed to get instance")
	}

	if instance == nil {
		// The machine hasn't been created yet
		klog.Info("Instance is nil and therefore does not exist")
		return nil
	}

	// Check the instance state. If it's already shutting down or terminated,
	// do nothing. Otherwise attempt to delete it.
	// This decision is based on the ec2-instance-lifecycle graph at
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html
	switch instance.State {
	case v1alpha1.InstanceStateShuttingDown, v1alpha1.InstanceStateTerminated:
		klog.Infof("instance %q is shutting down or already terminated", machine.Name)
		return nil
	default:
		if err := scope.EC2.TerminateInstance(aws.StringValue(scope.MachineStatus.InstanceID)); err != nil {
			return errors.Wrap(err, "failed to terminate instance")
		}
	}

	klog.Info("shutdown signal was sent. Shutting down machine.")
	return nil
}

// Update updates a machine and is invoked by the Machine Controller.
// If the Update attempts to mutate any immutable state, the method will error
// and no updates will be performed.
func (a *Actuator) Update(cluster *clusterv1.Cluster, machine *clusterv1.Machine) error {
	klog.Infof("Updating machine %v for cluster %v.", machine.Name, cluster.Name)

	scope, err := actuators.NewMachineScope(actuators.MachineScopeParams{Machine: machine, Cluster: cluster, Client: a.client})
	if err != nil {
		return err
	}

	defer scope.Close()

	// Get the current instance description from AWS.
	instanceDescription, err := scope.EC2.InstanceIfExists(scope.MachineStatus.InstanceID)
	if err != nil {
		return errors.Wrap(err, "failed to get instance")
	}

	// We can now compare the various AWS state to the state we were passed.
	// We will check immutable state first, in order to fail quickly before
	// moving on to state that we can mutate.
	// TODO: Implement immutable state check.

	// Ensure that the security groups are correct.
	_, err = a.ensureSecurityGroups(
		scope.EC2,
		machine,
		*scope.MachineStatus.InstanceID,
		scope.MachineConfig.AdditionalSecurityGroups,
		instanceDescription.SecurityGroupIDs,
	)
	if err != nil {
		return errors.Wrap(err, "failed to ensure security groups")
	}

	// Ensure that the tags are correct.
	_, err = a.ensureTags(scope.EC2, machine, scope.MachineStatus.InstanceID, scope.MachineConfig.AdditionalTags)
	if err != nil {
		return errors.Wrap(err, "failed to ensure tags")
	}

	return nil
}

// Exists test for the existence of a machine and is invoked by the Machine Controller
func (a *Actuator) Exists(cluster *clusterv1.Cluster, machine *clusterv1.Machine) (bool, error) {
	klog.Infof("Checking if machine %v for cluster %v exists", machine.Name, cluster.Name)

	scope, err := actuators.NewMachineScope(actuators.MachineScopeParams{Machine: machine, Cluster: cluster, Client: a.client})
	if err != nil {
		return false, err
	}

	defer scope.Close()

	// TODO worry about pointers. instance if exists returns *any* instance
	if scope.MachineStatus.InstanceID == nil {
		return false, nil
	}

	instance, err := scope.EC2.InstanceIfExists(scope.MachineStatus.InstanceID)
	if err != nil {
		return false, err
	}

	if instance == nil {
		return false, nil
	}

	klog.Infof("Found an instance: %v", instance)

	switch instance.State {
	case v1alpha1.InstanceStateRunning:
		klog.Infof("Machine %v is running", scope.MachineStatus.InstanceID)
	case v1alpha1.InstanceStatePending:
		klog.Infof("Machine %v is pending", scope.MachineStatus.InstanceID)
	default:
		return false, nil
	}

	if err := a.reconcileLBAttachment(scope, machine, instance); err != nil {
		return true, err
	}

	return true, nil
}
