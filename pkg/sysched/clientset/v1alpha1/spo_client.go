package v1alpha1

import (
    "k8s.io/apimachinery/pkg/runtime/schema"
    "k8s.io/client-go/kubernetes/scheme"
    "k8s.io/client-go/rest"
)

type SPOV1Alpha1Interface interface {
    Profiles() ProfileInterface
}

type SPOV1Alpha1Client struct {
    RestClient rest.Interface
}

func NewForConfig(c *rest.Config) (*SPOV1Alpha1Client, error) {
    config := *c
    config.GroupVersion = &schema.GroupVersion{Group: "security-profiles-operator.x-k8s.io", Version: "v1beta1"}
    config.APIPath = "/apis"
    config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
    if config.UserAgent == "" {
        config.UserAgent = rest.DefaultKubernetesUserAgent()
    }

    client, err := rest.RESTClientFor(&config)
    if err != nil {
        return nil, err
    }

    return &SPOV1Alpha1Client{RestClient: client}, nil
}

func (c *SPOV1Alpha1Client) Profiles() ProfileInterface {
    return &profileClient{
        restClient: c.RestClient,
    }
}
