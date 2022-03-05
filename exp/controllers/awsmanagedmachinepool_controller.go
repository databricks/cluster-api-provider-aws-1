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

package controllers

import (
	"context"
	"encoding/json"
	"fmt"

	"sigs.k8s.io/cluster-api/util/annotations"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	ekscontrolplanev1 "sigs.k8s.io/cluster-api-provider-aws/controlplane/eks/api/v1beta1"
	expinfrav1 "sigs.k8s.io/cluster-api-provider-aws/exp/api/v1beta1"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/scope"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/services"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/services/ec2"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/services/eks"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/cloud/services/userdata"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	expclusterv1 "sigs.k8s.io/cluster-api/exp/api/v1beta1"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/cluster-api/util/conditions"
	"sigs.k8s.io/cluster-api/util/predicates"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// AWSManagedMachinePoolReconciler reconciles a AWSManagedMachinePool object.
type AWSManagedMachinePoolReconciler struct {
	client.Client
	Recorder             record.EventRecorder
	Endpoints            []scope.ServiceEndpoint
	EnableIAM            bool
	AllowAdditionalRoles bool
	WatchFilterValue     string
}

// SetupWithManager is used to setup the controller.
func (r *AWSManagedMachinePoolReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, options controller.Options) error {
	log := ctrl.LoggerFrom(ctx)

	gvk, err := apiutil.GVKForObject(new(expinfrav1.AWSManagedMachinePool), mgr.GetScheme())
	if err != nil {
		return errors.Wrapf(err, "failed to find GVK for AWSManagedMachinePool")
	}
	managedControlPlaneToManagedMachinePoolMap := managedControlPlaneToManagedMachinePoolMapFunc(r.Client, gvk, log)
	return ctrl.NewControllerManagedBy(mgr).
		For(&expinfrav1.AWSManagedMachinePool{}).
		WithOptions(options).
		WithEventFilter(predicates.ResourceNotPausedAndHasFilterLabel(log, r.WatchFilterValue)).
		Watches(
			&source.Kind{Type: &expclusterv1.MachinePool{}},
			handler.EnqueueRequestsFromMapFunc(machinePoolToInfrastructureMapFunc(gvk)),
		).
		Watches(
			&source.Kind{Type: &ekscontrolplanev1.AWSManagedControlPlane{}},
			handler.EnqueueRequestsFromMapFunc(managedControlPlaneToManagedMachinePoolMap),
		).
		Complete(r)
}

// +kubebuilder:rbac:groups=cluster.x-k8s.io,resources=machinepools;machinepools/status,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups=controlplane.cluster.x-k8s.io,resources=awsmanagedcontrolplanes;awsmanagedcontrolplanes/status,verbs=get;list;watch
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=awsmanagedmachinepools,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=awsmanagedmachinepools/status,verbs=get;update;patch

// Reconcile reconciles AWSManagedMachinePools.
func (r *AWSManagedMachinePoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	log := ctrl.LoggerFrom(ctx)

	awsPool := &expinfrav1.AWSManagedMachinePool{}
	if err := r.Get(ctx, req.NamespacedName, awsPool); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{Requeue: true}, nil
	}

	machinePool, err := getOwnerMachinePool(ctx, r.Client, awsPool.ObjectMeta)
	if err != nil {
		log.Error(err, "Failed to retrieve owner MachinePool from the API Server")
		return ctrl.Result{}, err
	}
	if machinePool == nil {
		log.Info("MachinePool Controller has not yet set OwnerRef")
		return ctrl.Result{}, nil
	}

	log = log.WithValues("MachinePool", machinePool.Name)

	cluster, err := util.GetClusterFromMetadata(ctx, r.Client, machinePool.ObjectMeta)
	if err != nil {
		log.Info("Failed to retrieve Cluster from MachinePool")
		return reconcile.Result{}, nil
	}
	if annotations.IsPaused(cluster, awsPool) {
		log.Info("Reconciliation is paused for this object")
		return ctrl.Result{}, nil
	}

	log = log.WithValues("Cluster", cluster.Name)

	controlPlaneKey := client.ObjectKey{
		Namespace: awsPool.Namespace,
		Name:      cluster.Spec.ControlPlaneRef.Name,
	}
	controlPlane := &ekscontrolplanev1.AWSManagedControlPlane{}
	if err := r.Client.Get(ctx, controlPlaneKey, controlPlane); err != nil {
		log.Info("Failed to retrieve ControlPlane from MachinePool")
		return reconcile.Result{}, nil
	}

	managedControlPlaneScope, err := scope.NewManagedControlPlaneScope(scope.ManagedControlPlaneScopeParams{
		Client:         r.Client,
		Logger:         log,
		Cluster:        cluster,
		ControlPlane:   controlPlane,
		ControllerName: "awsManagedControlPlane",
	})
	if err != nil {
		return ctrl.Result{}, errors.New("error getting managed control plane scope")
	}

	if !controlPlane.Status.Ready {
		log.Info("Control plane is not ready yet")
		conditions.MarkFalse(awsPool, expinfrav1.EKSNodegroupReadyCondition, expinfrav1.WaitingForEKSControlPlaneReason, clusterv1.ConditionSeverityInfo, "")
		return ctrl.Result{}, nil
	}

	machinePoolScope, err := scope.NewManagedMachinePoolScope(scope.ManagedMachinePoolScopeParams{
		Client:               r.Client,
		ControllerName:       "awsmanagedmachinepool",
		Cluster:              cluster,
		ControlPlane:         controlPlane,
		MachinePool:          machinePool,
		ManagedMachinePool:   awsPool,
		EnableIAM:            r.EnableIAM,
		AllowAdditionalRoles: r.AllowAdditionalRoles,
		Endpoints:            r.Endpoints,
		InfraCluster:         managedControlPlaneScope,
	})
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "failed to create scope")
	}

	defer func() {
		applicableConditions := []clusterv1.ConditionType{
			expinfrav1.EKSNodegroupReadyCondition,
			expinfrav1.IAMNodegroupRolesReadyCondition,
			expinfrav1.LaunchTemplateReadyCondition,
		}

		conditions.SetSummary(machinePoolScope.ManagedMachinePool, conditions.WithConditions(applicableConditions...), conditions.WithStepCounter())

		if err := machinePoolScope.Close(); err != nil && reterr == nil {
			reterr = err
		}
	}()

	if !awsPool.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, machinePoolScope, managedControlPlaneScope)
	}

	return r.reconcileNormal(ctx, machinePoolScope, managedControlPlaneScope)
}

func (r *AWSManagedMachinePoolReconciler) reconcileNormal(
	_ context.Context,
	machinePoolScope *scope.ManagedMachinePoolScope,
	ec2Scope scope.EC2Scope,
) (ctrl.Result, error) {
	machinePoolScope.Info("Reconciling AWSManagedMachinePool")

	controllerutil.AddFinalizer(machinePoolScope.ManagedMachinePool, expinfrav1.ManagedMachinePoolFinalizer)
	if err := machinePoolScope.PatchObject(); err != nil {
		return ctrl.Result{}, err
	}

	ekssvc := eks.NewNodegroupService(machinePoolScope)

	if machinePoolScope.ManagedMachinePool.Spec.AWSLaunchTemplate != nil {
		if err := r.reconcileLaunchTemplate(machinePoolScope, ec2Scope); err != nil {
			r.Recorder.Eventf(machinePoolScope.ManagedMachinePool, corev1.EventTypeWarning, "FailedLaunchTemplateReconcile", "Failed to reconcile launch template: %v", err)
			machinePoolScope.Error(err, "failed to reconcile launch template")
			return ctrl.Result{}, err
		}

		if err := r.reconcileTags(machinePoolScope, ec2Scope); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "error updating tags")
		}

		// set the LaunchTemplateReady condition
		conditions.MarkTrue(machinePoolScope.ManagedMachinePool, expinfrav1.LaunchTemplateReadyCondition)
	}

	if err := ekssvc.ReconcilePool(); err != nil {
		return reconcile.Result{}, errors.Wrapf(err, "failed to reconcile machine pool for AWSManagedMachinePool %s/%s", machinePoolScope.ManagedMachinePool.Namespace, machinePoolScope.ManagedMachinePool.Name)
	}

	return ctrl.Result{}, nil
}

func (r *AWSManagedMachinePoolReconciler) reconcileDelete(
	_ context.Context,
	machinePoolScope *scope.ManagedMachinePoolScope,
	ec2Scope scope.EC2Scope,
) (ctrl.Result, error) {
	machinePoolScope.Info("Reconciling deletion of AWSManagedMachinePool")

	ekssvc := eks.NewNodegroupService(machinePoolScope)
	ec2Svc := ec2.NewService(ec2Scope)

	if err := ekssvc.ReconcilePoolDelete(); err != nil {
		return reconcile.Result{}, errors.Wrapf(err, "failed to reconcile machine pool deletion for AWSManagedMachinePool %s/%s", machinePoolScope.ManagedMachinePool.Namespace, machinePoolScope.ManagedMachinePool.Name)
	}

	if machinePoolScope.ManagedMachinePool.Spec.AWSLaunchTemplate != nil {
		launchTemplateID := machinePoolScope.ManagedMachinePool.Status.LaunchTemplateID
		launchTemplate, _, err := ec2Svc.GetLaunchTemplate(machinePoolScope.LaunchTemplateScope.Name())
		if err != nil {
			return ctrl.Result{}, err
		}

		if launchTemplate == nil {
			machinePoolScope.V(2).Info("Unable to locate launch template")
			r.Recorder.Eventf(machinePoolScope.ManagedMachinePool, corev1.EventTypeNormal, "NoLaunchTemplateFound", "Unable to find matching launch template")
			controllerutil.RemoveFinalizer(machinePoolScope.ManagedMachinePool, expinfrav1.ManagedMachinePoolFinalizer)
			return ctrl.Result{}, nil
		}

		machinePoolScope.Info("deleting launch template", "name", launchTemplate.Name)
		if err := ec2Svc.DeleteLaunchTemplate(*launchTemplateID); err != nil {
			r.Recorder.Eventf(machinePoolScope.ManagedMachinePool, corev1.EventTypeWarning, "FailedDelete", "Failed to delete launch template %q: %v", launchTemplate.Name, err)
			return ctrl.Result{}, errors.Wrap(err, "failed to delete launch template")
		}

		machinePoolScope.Info("successfully deleted launch template")
	}

	controllerutil.RemoveFinalizer(machinePoolScope.ManagedMachinePool, expinfrav1.ManagedMachinePoolFinalizer)

	return reconcile.Result{}, nil
}

// GetOwnerClusterKey returns only the Cluster name and namespace.
func GetOwnerClusterKey(obj metav1.ObjectMeta) (*client.ObjectKey, error) {
	for _, ref := range obj.OwnerReferences {
		if ref.Kind != "Cluster" {
			continue
		}
		gv, err := schema.ParseGroupVersion(ref.APIVersion)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if gv.Group == clusterv1.GroupVersion.Group {
			return &client.ObjectKey{
				Namespace: obj.Namespace,
				Name:      ref.Name,
			}, nil
		}
	}
	return nil, nil
}

func managedControlPlaneToManagedMachinePoolMapFunc(c client.Client, gvk schema.GroupVersionKind, log logr.Logger) handler.MapFunc {
	return func(o client.Object) []reconcile.Request {
		ctx := context.Background()
		awsControlPlane, ok := o.(*ekscontrolplanev1.AWSManagedControlPlane)
		if !ok {
			panic(fmt.Sprintf("Expected a AWSManagedControlPlane but got a %T", o))
		}

		if !awsControlPlane.ObjectMeta.DeletionTimestamp.IsZero() {
			return nil
		}

		clusterKey, err := GetOwnerClusterKey(awsControlPlane.ObjectMeta)
		if err != nil {
			log.Error(err, "couldn't get AWS control plane owner ObjectKey")
			return nil
		}
		if clusterKey == nil {
			return nil
		}

		managedPoolForClusterList := expclusterv1.MachinePoolList{}
		if err := c.List(
			ctx, &managedPoolForClusterList, client.InNamespace(clusterKey.Namespace), client.MatchingLabels{clusterv1.ClusterLabelName: clusterKey.Name},
		); err != nil {
			log.Error(err, "couldn't list pools for cluster")
			return nil
		}

		mapFunc := machinePoolToInfrastructureMapFunc(gvk)

		var results []ctrl.Request
		for i := range managedPoolForClusterList.Items {
			managedPool := mapFunc(&managedPoolForClusterList.Items[i])
			results = append(results, managedPool...)
		}

		return results
	}
}

func (r *AWSManagedMachinePoolReconciler) getEC2Service(scope scope.EC2Scope) services.EC2MachineInterface {
	return ec2.NewService(scope)
}

func (r *AWSManagedMachinePoolReconciler) reconcileLaunchTemplate(machinePoolScope *scope.ManagedMachinePoolScope, ec2Scope scope.EC2Scope) error {
	bootstrapData, err := machinePoolScope.GetRawBootstrapData()
	if err != nil {
		r.Recorder.Eventf(machinePoolScope.ManagedMachinePool, corev1.EventTypeWarning, "FailedGetBootstrapData", err.Error())
	}
	bootstrapDataHash := userdata.ComputeHash(bootstrapData)

	ec2svc := r.getEC2Service(ec2Scope)

	machinePoolScope.Info("checking for existing launch template")
	launchTemplate, launchTemplateUserDataHash, err := ec2svc.GetLaunchTemplate(machinePoolScope.LaunchTemplateScope.Name())
	if err != nil {
		conditions.MarkUnknown(machinePoolScope.ManagedMachinePool, expinfrav1.LaunchTemplateReadyCondition, expinfrav1.LaunchTemplateNotFoundReason, err.Error())
		return err
	}

	imageID, err := ec2svc.DiscoverLaunchTemplateAMI(machinePoolScope.LaunchTemplateScope)
	if err != nil {
		conditions.MarkFalse(machinePoolScope.ManagedMachinePool, expinfrav1.LaunchTemplateReadyCondition, expinfrav1.LaunchTemplateCreateFailedReason, clusterv1.ConditionSeverityError, err.Error())
		return err
	}

	if launchTemplate == nil {
		machinePoolScope.Info("no existing launch template found, creating")
		launchTemplateID, err := ec2svc.CreateLaunchTemplate(machinePoolScope.LaunchTemplateScope, imageID, bootstrapData)
		if err != nil {
			conditions.MarkFalse(machinePoolScope.ManagedMachinePool, expinfrav1.LaunchTemplateReadyCondition, expinfrav1.LaunchTemplateCreateFailedReason, clusterv1.ConditionSeverityError, err.Error())
			return err
		}

		machinePoolScope.SetLaunchTemplateIDStatus(launchTemplateID)
		return machinePoolScope.PatchObject()
	}

	// LaunchTemplateID is set during LaunchTemplate creation, but for a scenario such as `clusterctl move`, status fields become blank.
	// If launchTemplate already exists but LaunchTemplateID field in the status is empty, get the ID and update the status.
	if machinePoolScope.ManagedMachinePool.Status.LaunchTemplateID == nil {
		launchTemplateID, err := ec2svc.GetLaunchTemplateID(machinePoolScope.LaunchTemplateScope.Name())
		if err != nil {
			conditions.MarkUnknown(machinePoolScope.ManagedMachinePool, expinfrav1.LaunchTemplateReadyCondition, expinfrav1.LaunchTemplateNotFoundReason, err.Error())
			return err
		}
		machinePoolScope.SetLaunchTemplateIDStatus(launchTemplateID)
		return machinePoolScope.PatchObject()
	}

	if machinePoolScope.ManagedMachinePool.Status.LaunchTemplateVersion == nil {
		launchTemplateVersion, err := ec2svc.GetLaunchTemplateLatestVersion(*machinePoolScope.ManagedMachinePool.Status.LaunchTemplateID)
		if err != nil {
			conditions.MarkUnknown(machinePoolScope.ManagedMachinePool, expinfrav1.LaunchTemplateReadyCondition, expinfrav1.LaunchTemplateNotFoundReason, err.Error())
			return err
		}
		machinePoolScope.SetLaunchTemplateVersionStatus(launchTemplateVersion)
		return machinePoolScope.PatchObject()
	}

	annotation, err := r.machinePoolAnnotationJSON(machinePoolScope.ManagedMachinePool, TagsLastAppliedAnnotation)
	if err != nil {
		return err
	}

	// Check if the instance tags were changed. If they were, create a new LaunchTemplate.
	tagsChanged, _, _, _ := tagsChanged(annotation, machinePoolScope.LaunchTemplateScope.AdditionalTags()) // nolint:dogsled

	needsUpdate, err := ec2svc.LaunchTemplateNeedsUpdate(machinePoolScope.LaunchTemplateScope, machinePoolScope.LaunchTemplateScope.AWSLaunchTemplate, launchTemplate)
	if err != nil {
		return err
	}

	// Create a new launch template version if there's a difference in configuration, tags,
	// userdata, OR we've discovered a new AMI ID.
	if needsUpdate || tagsChanged || *imageID != *launchTemplate.AMI.ID || launchTemplateUserDataHash != bootstrapDataHash {
		machinePoolScope.Info("creating new version for launch template", "existing", launchTemplate, "incoming", machinePoolScope.LaunchTemplateScope.AWSLaunchTemplate)
		// There is a limit to the number of Launch Template Versions.
		// We ensure that the number of versions does not grow without bound by following a simple rule: Before we create a new version, we delete one old version, if there is at least one old version that is not in use.
		if err := ec2svc.PruneLaunchTemplateVersions(*machinePoolScope.ManagedMachinePool.Status.LaunchTemplateID); err != nil {
			return err
		}
		if err := ec2svc.CreateLaunchTemplateVersion(machinePoolScope.ManagedMachinePool.Status.LaunchTemplateID, machinePoolScope.LaunchTemplateScope, imageID, bootstrapData); err != nil {
			return err
		}
		version, err := ec2svc.GetLaunchTemplateLatestVersion(*machinePoolScope.ManagedMachinePool.Status.LaunchTemplateID)
		if err != nil {
			return err
		}
		machinePoolScope.SetLaunchTemplateVersionStatus(version)
		return machinePoolScope.PatchObject()
	}

	return nil
}

func (r *AWSManagedMachinePoolReconciler) reconcileTags(machinePoolScope *scope.ManagedMachinePoolScope, ec2Scope scope.EC2Scope) error {
	ec2Svc := r.getEC2Service(ec2Scope)

	launchTemplateID := machinePoolScope.ManagedMachinePool.Status.LaunchTemplateID
	additionalTags := machinePoolScope.LaunchTemplateScope.AdditionalTags()

	tagsChanged, err := r.ensureTags(ec2Svc, machinePoolScope.ManagedMachinePool, launchTemplateID, additionalTags)
	if err != nil {
		return err
	}
	if tagsChanged {
		r.Recorder.Eventf(machinePoolScope.ManagedMachinePool, corev1.EventTypeNormal, "UpdatedTags", "updated tags on resources")
	}
	return nil
}

func (r *AWSManagedMachinePoolReconciler) machinePoolAnnotationJSON(machinePool *expinfrav1.AWSManagedMachinePool, annotation string) (map[string]interface{}, error) {
	out := map[string]interface{}{}

	jsonAnnotation := r.machinePoolAnnotation(machinePool, annotation)
	if len(jsonAnnotation) == 0 {
		return out, nil
	}

	err := json.Unmarshal([]byte(jsonAnnotation), &out)
	if err != nil {
		return out, err
	}

	return out, nil
}

func (r *AWSManagedMachinePoolReconciler) machinePoolAnnotation(machinePool *expinfrav1.AWSManagedMachinePool, annotation string) string {
	return machinePool.GetAnnotations()[annotation]
}

func (r *AWSManagedMachinePoolReconciler) updateMachinePoolAnnotationJSON(machinePool *expinfrav1.AWSManagedMachinePool, annotation string, content map[string]interface{}) error {
	b, err := json.Marshal(content)
	if err != nil {
		return err
	}

	r.updateMachinePoolAnnotation(machinePool, annotation, string(b))
	return nil
}

func (r *AWSManagedMachinePoolReconciler) updateMachinePoolAnnotation(machinePool *expinfrav1.AWSManagedMachinePool, annotation, content string) {
	// Get the annotations
	annotations := machinePool.GetAnnotations()

	if annotations == nil {
		annotations = make(map[string]string)
	}

	// Set our annotation to the given content.
	annotations[annotation] = content

	// Update the machine object with these annotations
	machinePool.SetAnnotations(annotations)
}

func (r *AWSManagedMachinePoolReconciler) ensureTags(ec2svc services.EC2MachineInterface, machinePool *expinfrav1.AWSManagedMachinePool, launchTemplateID *string, additionalTags map[string]string) (bool, error) {
	annotation, err := r.machinePoolAnnotationJSON(machinePool, TagsLastAppliedAnnotation)
	if err != nil {
		return false, err
	}

	// Check if the instance tags were changed. If they were, update them.
	// It would be possible here to only send new/updated tags, but for the
	// moment we send everything, even if only a single tag was created or
	// upated.
	changed, created, deleted, newAnnotation := tagsChanged(annotation, additionalTags)
	if changed {
		err := ec2svc.UpdateResourceTags(launchTemplateID, created, deleted)
		if err != nil {
			return false, err
		}

		// We also need to update the annotation if anything changed.
		err = r.updateMachinePoolAnnotationJSON(machinePool, TagsLastAppliedAnnotation, newAnnotation)
		if err != nil {
			return false, err
		}
	}

	return changed, nil
}
