package v1alpha1

import (
	"context"
        "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

type ProfileInterface interface {
	Get(name string, ns string, options metav1.GetOptions) (*v1beta1.SeccompProfile, error)
}

type profileClient struct {
	restClient rest.Interface
}

func (c *profileClient) Get(name string, ns string, opts metav1.GetOptions) (*v1beta1.SeccompProfile, error) {
	result := v1beta1.SeccompProfile{}
	err := c.restClient.
		Get().
		Namespace(ns).
		Resource("seccompprofiles").
		Name(name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Do(context.TODO()).
		Into(&result)

	return &result, err
}
