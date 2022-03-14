package k8s

import (
	"fmt"
	"testing"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/rest"

	"istio.io/istio/pilot/pkg/config/kube/crdclient"
	"istio.io/istio/pilot/pkg/model"
	istioconfig "istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
	istiogvk "istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube"
	kubelib "istio.io/istio/pkg/kube"
	"istio.io/pkg/log"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func foo(client kubelib.Client) {
	stopCh := make(chan struct{})
	factory := informers.NewSharedInformerFactoryWithOptions(client, time.Second*30,
		informers.WithNamespace(meta_v1.NamespaceAll))
	informer := factory.Core().V1().Namespaces().Informer()
	factory.Start(stopCh)
	if !cache.WaitForCacheSync(stopCh,
		informer.HasSynced) {
		panic(fmt.Errorf("failed to sync caches for namesapce informers"))
	}
	// nsList, err := factory.Core().V1().Namespaces().Lister().List(k8sApiLabels.Everything())
	// if err != nil {
	// 	panic(fmt.Errorf("sharedInformer for namespaces failed listing namespaces"))
	// }
	// c.Lock()
	// for _, ns := range nsList {
	// 	c.namespaces[ns.Name] = struct{}{}
	// }
	// c.Unlock()
	informer.AddEventHandler(&namespaceHandler{})
	time.Sleep(time.Second * 3600)
}

func makeClient(t *testing.T, schemas collection.Schemas) (model.ConfigStoreCache, kube.ExtendedClient) {
	kubeRestConfig, err := kubelib.DefaultRestConfig("/home/fly/.kube/config", "", func(config *rest.Config) {
		// config.QPS =
		// config.Burst = 40
	})
	if err != nil {
		t.Fatal(err)
	}
	kubeclient := kubelib.NewClientConfigForRestConfig(kubeRestConfig)
	istioKubeClient, err := kubelib.NewExtendedClient(kubelib.NewClientConfigForRestConfig(kubeRestConfig), "")
	if err != nil {
		log.Fatalf("failed creating istio kube client: %v", err)
	}
	go foo(istioKubeClient)
	fake, err := kubelib.NewExtendedClient(kubeclient, "")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	config, err := crdclient.New(fake, "", "")
	config.RegisterEventHandler(istiogvk.AuthorizationPolicy, func(
		old istioconfig.Config, new istioconfig.Config, e model.Event) {
		log.Infof("jianfeih debug the event handler, event %v, config %v\n", e, new)
	})

	go func() {
		for {
			log.Infof("jianfeih print out all names")
			configs, err := config.List(istiogvk.AuthorizationPolicy, "foo")
			if err == nil {
				for _, c := range configs {
					log.Infof("jianfeih debug the config name %v", c.Name)
				}
			}
			time.Sleep(time.Second * 5)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}
	go config.Run(stop)
	fake.RunAndWait(stop)
	cache.WaitForCacheSync(stop, config.HasSynced)
	t.Cleanup(func() {
		close(stop)
	})
	time.Sleep(time.Second * 36000)
	return config, fake
}

// CheckIstioConfigTypes validates that an empty store can do CRUD operators on all given types
func TestClient(t *testing.T) {
	_, _ = makeClient(t, collections.PilotGatewayAPI.Union(collections.Kube))
}
