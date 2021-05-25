/*
Copyright 2021 The Kubernetes Authors.

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

package addons

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/eks"
)

var (
	// ErrNilAddon defines an error for when a nil addon is returned.
	ErrNilAddon = errors.New("nil addon returned from create")
	// ErrAddonNotFound defines an error for when an addon is not found.
	ErrAddonNotFound = errors.New("addon not found")
	// ErrAddonAlreadyExists defines an error for when an addon already exists.
	ErrAddonAlreadyExists = errors.New("addon already exists")
)

// DeleteAddonProcedure is a procedure that will delete an EKS addon
type DeleteAddonProcedure struct {
	plan *plan
	name string
}

// Do implements the logic for the procedure
func (p *DeleteAddonProcedure) Do(ctx context.Context) error {
	input := &eks.DeleteAddonInput{
		AddonName:   aws.String(p.name),
		ClusterName: aws.String(p.plan.clusterName),
	}

	_, err := p.plan.eksClient.DeleteAddon(input)
	if err != nil {
		return fmt.Errorf("deleting eks addon %s: %w", p.name, err)
	}

	return nil
}

// Name is the name of the procedure
func (p *DeleteAddonProcedure) Name() string {
	return "addon_delete"
}

// UpdateAddonProcedure is a procedure that will update an EKS addon
type UpdateAddonProcedure struct {
	plan *plan
	name string
}

// Do implements the logic for the procedure
func (p *UpdateAddonProcedure) Do(ctx context.Context) error {
	desired := p.plan.getDesired(p.name)

	if desired == nil {
		return fmt.Errorf("getting desired addon %s: %w", p.name, ErrAddonNotFound)
	}

	input := &eks.UpdateAddonInput{
		AddonName:             desired.Name,
		AddonVersion:          desired.Version,
		ClusterName:           &p.plan.clusterName,
		ResolveConflicts:      desired.ResolveConflict,
		ServiceAccountRoleArn: desired.ServiceAccountRoleARN,
	}
	_, err := p.plan.eksClient.UpdateAddon(input)
	if err != nil {
		return fmt.Errorf("updating eks addon %s: %w", p.name, err)
	}

	return nil
}

// Name is the name of the procedure
func (p *UpdateAddonProcedure) Name() string {
	return "addon_update"
}

// UpdateAddonTagsProcedure is a procedure that will update an EKS addon tags
type UpdateAddonTagsProcedure struct {
	plan *plan
	name string
}

// Do implements the logic for the procedure
func (p *UpdateAddonTagsProcedure) Do(ctx context.Context) error {
	desired := p.plan.getDesired(p.name)
	installed := p.plan.getInstalled(p.name)

	if desired == nil {
		return fmt.Errorf("getting desired addon %s: %w", p.name, ErrAddonNotFound)
	}
	if installed == nil {
		return fmt.Errorf("getting installed addon %s: %w", p.name, ErrAddonNotFound)
	}

	input := &eks.TagResourceInput{
		ResourceArn: installed.ARN,
		Tags:        convertTags(desired.Tags),
	}
	_, err := p.plan.eksClient.TagResource(input)
	if err != nil {
		return fmt.Errorf("updating eks addon tags %s: %w", p.name, err)
	}

	return nil
}

// Name is the name of the procedure
func (p *UpdateAddonTagsProcedure) Name() string {
	return "addon_tags_update"
}

// CreateAddonProcedure is a procedure that will create an EKS addon for a cluster
type CreateAddonProcedure struct {
	plan *plan
	name string
}

// Do implements the logic for the procedure
func (p *CreateAddonProcedure) Do(ctx context.Context) error {
	desired := p.plan.getDesired(p.name)
	if desired == nil {
		return fmt.Errorf("getting desired addon %s: %w", p.name, ErrAddonNotFound)
	}

	input := &eks.CreateAddonInput{
		AddonName:             desired.Name,
		AddonVersion:          desired.Version,
		ClusterName:           &p.plan.clusterName,
		ServiceAccountRoleArn: desired.ServiceAccountRoleARN,
		ResolveConflicts:      desired.ResolveConflict,
		Tags:                  convertTags(desired.Tags),
	}

	output, err := p.plan.eksClient.CreateAddon(input)
	if err != nil {
		return fmt.Errorf("creating eks addon %s: %w", p.name, err)
	}

	if output.Addon == nil {
		return ErrNilAddon
	}

	return nil
}

// Name is the name of the procedure
func (p *CreateAddonProcedure) Name() string {
	return "addon_create"
}

// WaitAddonActiveProcedure is a procedure that will wait for an EKS addon
// to be active in a cluster
type WaitAddonActiveProcedure struct {
	plan *plan
	name string
}

// Do implements the logic for the procedure
func (p *WaitAddonActiveProcedure) Do(ctx context.Context) error {
	input := &eks.DescribeAddonInput{
		AddonName:   aws.String(p.name),
		ClusterName: aws.String(p.plan.clusterName),
	}

	if err := p.plan.eksClient.WaitUntilAddonActive(input); err != nil {
		return fmt.Errorf("waiting for addon %s to be active: %w", p.name, err)
	}

	return nil
}

// Name is the name of the procedure
func (p *WaitAddonActiveProcedure) Name() string {
	return "addon_wait_active"
}

// WaitAddonDeleteProcedure is a procedure that will wait for an EKS addon
// to be deleted from a cluster
type WaitAddonDeleteProcedure struct {
	plan *plan
	name string
}

// Do implements the logic for the procedure
func (p *WaitAddonDeleteProcedure) Do(ctx context.Context) error {
	input := &eks.DescribeAddonInput{
		AddonName:   aws.String(p.name),
		ClusterName: aws.String(p.plan.clusterName),
	}

	if err := p.plan.eksClient.WaitUntilAddonDeleted(input); err != nil {
		return fmt.Errorf("waiting for addon %s to be deleted: %w", p.name, err)
	}

	return nil
}

// Name is the name of the procedure
func (p *WaitAddonDeleteProcedure) Name() string {
	return "addon_wait_delete"
}
