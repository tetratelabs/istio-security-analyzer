package k8s

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/rest"

	"github.com/tetratelabs/istio-security-scanner/pkg/parser"

	"istio.io/istio/pilot/pkg/config/kube/crdclient"
	"istio.io/istio/pilot/pkg/model"
	istioconfig "istio.io/istio/pkg/config"
	istiogvk "istio.io/istio/pkg/config/schema/gvk"
	kubelib "istio.io/istio/pkg/kube"
	"istio.io/pkg/log"

	smodel "github.com/tetratelabs/istio-security-scanner/pkg/model"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type Client struct {
	configStore model.ConfigStoreCache
	kubeClient  kubelib.ExtendedClient
	nsInformer  cache.SharedIndexInformer
	nsHandler   cache.ResourceEventHandler

	// mutex protects the access to `istioVersion` and `configIssues`.
	mu           sync.Mutex
	istioVersion string
	configIssues []error
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

	configStore, err := crdclient.New(istioKubeClient, "default", "")
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
	go c.serveHTTPReport()
	for {
		istioVersion := "undefined"
		warnings := c.scanAll()
		// Hard code as istio-system for now. May need to change for multi revision deployments.
		v, err := c.kubeClient.GetIstioVersions(context.TODO(), "istio-system")
		if err != nil {
			log.Errorf("Failed to extract istio version: %v", err)
		} else {
			istioVersion = (*v)[0].Info.Version
		}

		c.mu.Lock()
		c.istioVersion = istioVersion
		c.configIssues = warnings
		log.Debugf("Updated Istio version %v, configIssues %v", c.istioVersion, c.configIssues)
		c.mu.Unlock()

		time.Sleep(time.Second * 10)
	}
}

func (c *Client) reportSecuritySummary(w http.ResponseWriter, req *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	report := smodel.RenderReport(c.istioVersion, c.configIssues)
	_, _ = w.Write([]byte(report))
}

func (c *Client) serveHTTPReport() {
	http.HandleFunc("/", c.reportSecuritySummary)
	if err := http.ListenAndServe("localhost:8080", nil); err != nil {
		log.Fatalf("Failed to serve http %v", err)
	}
}

func (c *Client) configByNamespace(gvk istioconfig.GroupVersionKind, ns string) []*istioconfig.Config {
	out := []*istioconfig.Config{}
	cfgs, err := c.configStore.List(gvk, ns)
	if err != nil {
		log.Errorf("Failed to list configuration %v in namespace %v: %v", gvk, ns, err)
		return out
	}
	for ind := range cfgs {
		out = append(out, &cfgs[ind])
	}
	return out
}

func (c *Client) scanAll() []error {
	log.Infof("Staring the new round of scanning.")
	// Iterate namespaces.
	configs := []*istioconfig.Config{}
	namespaces := c.nsInformer.GetIndexer().List()
	for _, obj := range namespaces {
		ns, ok := obj.(*corev1.Namespace)
		// Should not happen.
		if !ok {
			log.Errorf("Failed to convert to namespace: %v", obj)
		}
		log.Infof("Scan namespace %v", ns.Name)
		configs = append(configs, c.configByNamespace(istiogvk.AuthorizationPolicy, ns.Name)...)
		configs = append(configs, c.configByNamespace(istiogvk.DestinationRule, ns.Name)...)
	}
	errs := parser.CheckAll(configs)
	log.Infof("Finish scanning: number of errors %v", len(errs))
	return errs
}