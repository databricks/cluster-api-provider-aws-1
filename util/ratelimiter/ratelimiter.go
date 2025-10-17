/*
Copyright 2022.

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

package ratelimiter

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ekscontrolplanev1 "sigs.k8s.io/cluster-api-provider-aws/controlplane/eks/api/v1beta1"
	expclusterv1 "sigs.k8s.io/cluster-api/exp/api/v1beta1"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/ratelimiter"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sync"
	"time"
)

const (
	// RateLimiterBucketSize is the default bucket size for bucket per group key.
	RateLimiterBucketSize = 10

	// RateLimiterRate is the default rate per second for bucket per group key.
	RateLimiterRate = 5

	// MaxBackoffDelay is the default max delay for backoff ratelimiter
	MaxBackoffDelay = 300 * time.Second
)

// PerAccountBucketRateLimiter returns a rate limiter that combines a per item exponential backoff rate limiter with a
// per-account bucket rate limiter.
func PerAccountBucketRateLimiter(k8sClient client.Client, log logr.Logger, groupKeyProvider GroupKeyProvider) ratelimiter.RateLimiter {
	return workqueue.NewMaxOfRateLimiter(
		// Initial backoff of 10s increasing to a max configured delay.
		workqueue.NewItemExponentialFailureRateLimiter(10*time.Second, MaxBackoffDelay),
		NewKeyedBucketRateLimiter(k8sClient, log, groupKeyProvider),
	)
}

// NewKeyedBucketRateLimiter returns a rate limiter that limits the number of requests by a group key.
// If the group key cannot be determined, the fallback limiter is used.
func NewKeyedBucketRateLimiter(k8sClient client.Client, log logr.Logger, groupKeyProvider GroupKeyProvider) *keyedBucketRateLimiter {
	return &keyedBucketRateLimiter{
		Client:           k8sClient,
		Log:              log,
		groupKeyProvider: groupKeyProvider,
		buckets:          make(map[string]*rate.Limiter),
		fallbackLimiter:  &workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(RateLimiterRate), RateLimiterBucketSize)},
	}
}

// keyedBucketRateLimiter is a rate limiter that limits the number of requests grouped by a key. For example, the
// key could be an account ID, and the rate limiter would limit the number of requests per account.
type keyedBucketRateLimiter struct {
	ratelimiter.RateLimiter
	Client client.Client
	Log    logr.Logger
	// groupKeyProvider returns the bucket group key for a given item.
	groupKeyProvider GroupKeyProvider

	bucketsLock sync.Mutex
	buckets     map[string]*rate.Limiter
	// fallbackLimiter is the global ratelimiter to use when the group key cannot be determined.
	fallbackLimiter ratelimiter.RateLimiter
}

// GroupKeyProvider returns the group key for a given item. If the group key cannot be determined, nil is returned.
// Returning nil will cause the item to be rate limited using the fallback limiter.
type GroupKeyProvider func(k8sClient client.Client, log logr.Logger, item types.NamespacedName) *string

func (r *keyedBucketRateLimiter) When(item interface{}) time.Duration {
	log := r.Log.WithValues("item", item)
	req, ok := item.(reconcile.Request)
	if !ok {
		// Item is not a reconcile Request, this should never happen. Log an error and use fallback limiter.
		log.Error(fmt.Errorf("cannot get account key for non reconcile request item"), "item is not a reconcile Request")
		return r.fallbackLimiter.When(item)
	}

	groupKey := r.groupKeyProvider(r.Client, log, req.NamespacedName)
	if groupKey == nil {
		// No group key, use the fallback limiter.
		log.Info("no group key, using fallback limiter", "item", item)
		return r.fallbackLimiter.When(item)
	}

	bucketLimiter := r.getRateLimiterForGroup(groupKey)
	log.V(1).Info("using per account rate limiter", "groupKey", *groupKey)
	return bucketLimiter.Reserve().Delay()
}

func (r *keyedBucketRateLimiter) getRateLimiterForGroup(groupKey *string) *rate.Limiter {
	r.bucketsLock.Lock()
	defer r.bucketsLock.Unlock()

	bucketLimiter, ok := r.buckets[*groupKey]
	if !ok {
		bucketLimiter = rate.NewLimiter(rate.Limit(RateLimiterRate), RateLimiterBucketSize)
		r.buckets[*groupKey] = bucketLimiter
	}
	return bucketLimiter
}

// NumRequeues returns back how many failures the item has had. From RateLimiter interface, and not used for bucket
// ratelimiter.
func (r *keyedBucketRateLimiter) NumRequeues(_ interface{}) int {
	return 0
}

// Forget indicates that an item has finished being retried. Doesn't do anything for bucket ratelimiter.
func (r *keyedBucketRateLimiter) Forget(_ interface{}) {
}

func GetGroupKeyFromManagedMachinePool(k8sClient client.Client, log logr.Logger, machinePoolName types.NamespacedName) *string {
	// Fetch the Machine Pool instance
	ctx := context.Background()
	mp := &expclusterv1.MachinePool{}
	if err := k8sClient.Get(ctx, machinePoolName, mp); err != nil {
		return nil
	}
	// Get the cluster from the Machine Pool
	cluster, err := util.GetClusterFromMetadata(ctx, k8sClient, mp.ObjectMeta)
	if err != nil {
		return nil
	}
	controlPlaneKey := client.ObjectKey{
		Namespace: machinePoolName.Namespace,
		Name:      cluster.Spec.ControlPlaneRef.Name,
	}
	return GetGroupKeyFromControlPlane(k8sClient, log, controlPlaneKey)
}

func GetGroupKeyFromControlPlane(k8sClient client.Client, log logr.Logger, controlPlaneKey types.NamespacedName) *string {
	controlPlane := &ekscontrolplanev1.AWSManagedControlPlane{}
	if err := k8sClient.Get(context.Background(), controlPlaneKey, controlPlane); err != nil {
		log.Error(err, "cannot get control plane instance")
		return nil
	}
	// Use the identity reference to get the group key, we use a separate IAM role per account, so this would group
	// by account.
	if controlPlane.Spec.IdentityRef != nil {
		return &controlPlane.Spec.IdentityRef.Name
	} else {
		return nil
	}
}
