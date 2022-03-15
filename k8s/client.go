package k8s

import (
	"context"
	"fmt"
	"time"

	"github.com/incfly/gotmpl/cve"
	"github.com/incfly/gotmpl/parser"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/rest"

	"istio.io/istio/pilot/pkg/config/kube/crdclient"
	"istio.io/istio/pilot/pkg/model"
	istioconfig "istio.io/istio/pkg/config"
	istiogvk "istio.io/istio/pkg/config/schema/gvk"
	kubelib "istio.io/istio/pkg/kube"
	"istio.io/pkg/log"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type Client struct {
	configStore model.ConfigStoreCache
	kubeClient  kubelib.ExtendedClient
	nsInformer  cache.SharedIndexInformer
	nsHandler   cache.ResourceEventHandler
}

type namespaceHandler struct{}

func (nh *namespaceHandler) OnAdd(obj interface{}) {
}

func (nh *namespaceHandler) OnUpdate(old interface{}, new interface{}) {
}

func (nh *namespaceHandler) OnDelete(delete interface{}) {
}

func istioClientFromKubeConfig(config string) (kubelib.ExtendedClient, error) {
	kubeRestConfig, err := kubelib.DefaultRestConfig(config, "", func(config *rest.Config) {
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %v", err)
	}
	istioKubeClient, err := kubelib.NewExtendedClient(
		kubelib.NewClientConfigForRestConfig(kubeRestConfig), "")
	if err != nil {
		return nil, err
	}
	return istioKubeClient, nil
}

func NewClient(kubeConfigPath string) (*Client, error) {
	istioKubeClient, err := istioClientFromKubeConfig(kubeConfigPath)
	if err != nil {
		return nil, err
	}
	factory := informers.NewSharedInformerFactoryWithOptions(istioKubeClient, time.Second*30,
		informers.WithNamespace(meta_v1.NamespaceAll))
	out := &Client{
		nsInformer: factory.Core().V1().Namespaces().Informer(),
		nsHandler:  &namespaceHandler{},
	}
	out.nsInformer.AddEventHandler(out.nsHandler)
	stopCh := make(chan struct{})
	factory.Start(stopCh)

	configStore, err := crdclient.New(istioKubeClient, "", "")
	if err != nil {
		return nil, err
	}
	configStore.RegisterEventHandler(istiogvk.AuthorizationPolicy, func(
		old istioconfig.Config, new istioconfig.Config, e model.Event) {
	})
	out.configStore = configStore
	out.kubeClient = istioKubeClient
	return out, nil
}

func IstioVersion(kubeConfig string) (string, error) {
	c, err := istioClientFromKubeConfig(kubeConfig)
	if err != nil {
		return "", err
	}
	version, err := c.GetIstioVersions(context.TODO(), "istio-system")
	if err != nil {
		return "", err
	}
	return (*version)[0].Info.Version, nil
}

func (c *Client) Run(stopCh chan struct{}) {
	log.Infof("Starting kubernetes client for scanning.")
	go c.configStore.Run(stopCh)
	go c.kubeClient.RunAndWait(stopCh)
	for {
		c.scanAll()
		// Hard code as istio-system for now. May need to change for multi revision deployments.
		v, err := c.kubeClient.GetIstioVersions(context.TODO(), "istio-system")
		if err != nil {
			log.Errorf("Failed to extract istio version: %v", err)
		} else {
			version := (*v)[0].Info.Version
			log.Infof("Istio version: %v", version)
			cves := cve.FindVunerabilities(version)
			log.Infof("CVE list: %v\n", cves)
		}
		time.Sleep(time.Second * 10)
	}
}

func (c *Client) scanAll() {
	log.Infof("Staring the new round of scanning.")
	// iterate namespaces.
	configs := []*istioconfig.Config{}
	namespaces := c.nsInformer.GetIndexer().List()
	for _, obj := range namespaces {
		ns, ok := obj.(*corev1.Namespace)
		// Should not happen.
		if !ok {
			log.Errorf("Failed to convert to namespace: %v", obj)
		}
		log.Debugf("Scan namespace %v", ns.Name)
		authz, err := c.configStore.List(istiogvk.AuthorizationPolicy, ns.Name)
		if err != nil {
			log.Errorf("Failed to list configuration authorization policy %v", err)
			continue
		}
		for _, cr := range authz {
			configs = append(configs, &cr)
		}
	}
	errs := parser.CheckAll(configs)
	if len(errs) != 0 {
		log.Infof("reporting error\n%v", errs)
	}
	log.Infof("Finish scanning.")
}
