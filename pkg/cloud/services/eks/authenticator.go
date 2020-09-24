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
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"

	"sigs.k8s.io/cluster-api/controllers/remote"
	"sigs.k8s.io/controller-runtime/pkg/client"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/api/v1alpha3"
	"sigs.k8s.io/cluster-api-provider-aws/pkg/iamauth"
)

func (s *Service) reconcileAuthenticator(ctx context.Context) error {
	s.scope.V(2).Info("Reconciling aws-iam-authenticator configuration", "cluster-name", s.scope.KubernetesClusterName())

	clusterKey := client.ObjectKey{
		Name:      s.scope.Cluster.Name,
		Namespace: s.scope.Cluster.Namespace,
	}

	accountID, err := s.getAccountID()
	if err != nil {
		return fmt.Errorf("getting account id: %w", err)
	}

	restConfig, err := remote.RESTConfig(ctx, s.scope.Client, clusterKey)
	if err != nil {
		return fmt.Errorf("getting remote client for %s/%s: %w", s.scope.Cluster.Namespace, s.scope.Cluster.Name, err)
	}

	remoteClient, err := client.New(restConfig, client.Options{})
	if err != nil {
		return fmt.Errorf("getting client for remote cluster: %w", err)
	}

	authBackend, err := iamauth.New(iamauth.BackendTypeConfigMap, remoteClient)
	if err != nil {
		return fmt.Errorf("getting aws-iam-authenticator backend: %w", err)
	}

	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/nodes%s", accountID, infrav1.DefaultNameSuffix)

	roleMapping := iamauth.RoleMapping{
		RoleARN: roleARN,
		KubernetesMapping: iamauth.KubernetesMapping{
			UserName: iamauth.EC2NodeUserName,
			Groups:   iamauth.NodeGroups,
		},
	}

	s.scope.V(2).Info("Mapping nodes role", "role", roleMapping.RoleARN, "user", roleMapping.UserName)
	if err := authBackend.MapRole(roleMapping); err != nil {
		return fmt.Errorf("mapping node role: %w", err)
	}

	s.scope.V(2).Info("Reconciled aws-iam-authenticator configuration", "cluster-name", s.scope.KubernetesClusterName())

	return nil
}

func (s *Service) getAccountID() (string, error) {
	input := &sts.GetCallerIdentityInput{}

	out, err := s.STSClient.GetCallerIdentity(input)
	if err != nil {
		return "", errors.Wrap(err, "unable to get caller identity")
	}

	return aws.StringValue(out.Account), nil
}
