/*
Copyright 2023 The Kubernetes Authors.

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

// This package imports things required by build scripts, to force `go mod` to see them as dependencies

// Code generated by client-gen. DO NOT EDIT.

package v1alpha2

import (
	"context"
	"time"

	v1alpha2 "github.com/k8stopologyawareschedwg/noderesourcetopology-api/pkg/apis/topology/v1alpha2"
	scheme "github.com/k8stopologyawareschedwg/noderesourcetopology-api/pkg/generated/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// NodeResourceTopologiesGetter has a method to return a NodeResourceTopologyInterface.
// A group's client should implement this interface.
type NodeResourceTopologiesGetter interface {
	NodeResourceTopologies() NodeResourceTopologyInterface
}

// NodeResourceTopologyInterface has methods to work with NodeResourceTopology resources.
type NodeResourceTopologyInterface interface {
	Create(ctx context.Context, nodeResourceTopology *v1alpha2.NodeResourceTopology, opts v1.CreateOptions) (*v1alpha2.NodeResourceTopology, error)
	Update(ctx context.Context, nodeResourceTopology *v1alpha2.NodeResourceTopology, opts v1.UpdateOptions) (*v1alpha2.NodeResourceTopology, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha2.NodeResourceTopology, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha2.NodeResourceTopologyList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha2.NodeResourceTopology, err error)
	NodeResourceTopologyExpansion
}

// nodeResourceTopologies implements NodeResourceTopologyInterface
type nodeResourceTopologies struct {
	client rest.Interface
}

// newNodeResourceTopologies returns a NodeResourceTopologies
func newNodeResourceTopologies(c *TopologyV1alpha2Client) *nodeResourceTopologies {
	return &nodeResourceTopologies{
		client: c.RESTClient(),
	}
}

// Get takes name of the nodeResourceTopology, and returns the corresponding nodeResourceTopology object, and an error if there is any.
func (c *nodeResourceTopologies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha2.NodeResourceTopology, err error) {
	result = &v1alpha2.NodeResourceTopology{}
	err = c.client.Get().
		Resource("noderesourcetopologies").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of NodeResourceTopologies that match those selectors.
func (c *nodeResourceTopologies) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha2.NodeResourceTopologyList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha2.NodeResourceTopologyList{}
	err = c.client.Get().
		Resource("noderesourcetopologies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested nodeResourceTopologies.
func (c *nodeResourceTopologies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("noderesourcetopologies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a nodeResourceTopology and creates it.  Returns the server's representation of the nodeResourceTopology, and an error, if there is any.
func (c *nodeResourceTopologies) Create(ctx context.Context, nodeResourceTopology *v1alpha2.NodeResourceTopology, opts v1.CreateOptions) (result *v1alpha2.NodeResourceTopology, err error) {
	result = &v1alpha2.NodeResourceTopology{}
	err = c.client.Post().
		Resource("noderesourcetopologies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(nodeResourceTopology).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a nodeResourceTopology and updates it. Returns the server's representation of the nodeResourceTopology, and an error, if there is any.
func (c *nodeResourceTopologies) Update(ctx context.Context, nodeResourceTopology *v1alpha2.NodeResourceTopology, opts v1.UpdateOptions) (result *v1alpha2.NodeResourceTopology, err error) {
	result = &v1alpha2.NodeResourceTopology{}
	err = c.client.Put().
		Resource("noderesourcetopologies").
		Name(nodeResourceTopology.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(nodeResourceTopology).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the nodeResourceTopology and deletes it. Returns an error if one occurs.
func (c *nodeResourceTopologies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("noderesourcetopologies").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *nodeResourceTopologies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("noderesourcetopologies").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched nodeResourceTopology.
func (c *nodeResourceTopologies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha2.NodeResourceTopology, err error) {
	result = &v1alpha2.NodeResourceTopology{}
	err = c.client.Patch(pt).
		Resource("noderesourcetopologies").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
