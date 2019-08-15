/*
Copyright 2019 The Kubernetes Authors.

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

package machine

import (
	"testing"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/klogr"
	clusterv1 "sigs.k8s.io/cluster-api/pkg/apis/cluster/v1alpha1"
)

func makeCM(t *testing.T, name, token string) *v1.ConfigMap {
	var cm v1.ConfigMap
	li := &LockInformation{
		MachineName:      name,
		IdempotencyToken: token,
	}

	if err := WriteLockInfo(&cm, li); err != nil {
		t.Fatalf("Unexpected error encoding configmap: %v", err)
	}

	return &cm
}

func TestControlPlaneInitLockerAcquireWithToken(t *testing.T) {
	const (
		machineName              = "my-machine-name"
		createdIdempotencyToken  = "my-created-token"
		existingIdempotencyToken = "my-existing-token"
	)

	tests := []struct {
		name        string
		configMap   *v1.ConfigMap
		getError    error
		createError error
		expectToken string
	}{
		{
			name:        "no config map exists",
			getError:    apierrors.NewNotFound(schema.GroupResource{Group: "", Resource: "configmaps"}, "uid1-configmap"),
			expectToken: createdIdempotencyToken,
		},
		{
			name:     "failed to retrieve",
			getError: errors.New("couldn't get error"),
		},
		{
			name:        "failed to create token",
			createError: errors.New("couldn't get error"),
		},
		{
			name:      "lock exists for other machine",
			configMap: makeCM(t, "some-other-machine", existingIdempotencyToken),
		},
		{
			name:        "locks exists for this machine",
			configMap:   makeCM(t, machineName, existingIdempotencyToken),
			expectToken: existingIdempotencyToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := &controlPlaneInitLocker{
				log: klogr.New(),
				configMapClient: &configMapsGetter{
					configMap:   tc.configMap,
					getError:    tc.getError,
					createError: tc.createError,
				},
			}

			l.random = func() string {
				return createdIdempotencyToken
			}

			cluster := &clusterv1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1",
					Name:      "name1",
					UID:       types.UID("uid1"),
				},
			}

			machine := &clusterv1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1",
					Name:      machineName,
					UID:       types.UID("uid2"),
				},
			}

			_, tok := l.AcquireWithToken(cluster, machine)
			if tc.expectToken != tok {
				t.Errorf("Expected token %q, but received %q", tc.expectToken, tok)
			}
		})
	}
}

type configMapsGetter struct {
	configMap   *v1.ConfigMap
	getError    error
	createError error
}

func (c *configMapsGetter) ConfigMaps(namespace string) corev1client.ConfigMapInterface {
	return &configMapClient{
		configMap:   c.configMap,
		getError:    c.getError,
		createError: c.createError,
	}
}

type configMapClient struct {
	configMap   *v1.ConfigMap
	getError    error
	createError error
}

func (c *configMapClient) Create(configMap *v1.ConfigMap) (*v1.ConfigMap, error) {
	return c.configMap, c.createError
}

func (c *configMapClient) Get(name string, getOptions metav1.GetOptions) (*v1.ConfigMap, error) {
	if c.getError != nil {
		return nil, c.getError
	}
	return c.configMap, nil
}

func (c *configMapClient) Update(*v1.ConfigMap) (*v1.ConfigMap, error) {
	panic("not implemented")
}

func (c *configMapClient) Delete(name string, options *metav1.DeleteOptions) error {
	panic("not implemented")
}

func (c *configMapClient) DeleteCollection(options *metav1.DeleteOptions, listOptions metav1.ListOptions) error {
	panic("not implemented")
}

func (c *configMapClient) List(opts metav1.ListOptions) (*v1.ConfigMapList, error) {
	panic("not implemented")
}

func (c *configMapClient) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	panic("not implemented")
}

func (c *configMapClient) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.ConfigMap, err error) {
	panic("not implemented")
}
