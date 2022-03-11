package k8s

import (
	"time"

	"istio.io/istio/pilot/pkg/config/kube/crdclient"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/collections"
	kubelib "istio.io/istio/pkg/kube"
	"istio.io/pkg/log"
	"k8s.io/client-go/rest"
)

type Client struct {
	configStore model.ConfigStoreCache
}

func NewClient(kubeClient string /*kubelib.Client*/) (*Client, error) {
	if s := log.FindScope("kube"); s != nil {
		s.SetOutputLevel(log.DebugLevel)
	}

	kubeRestConfig, err := kubelib.DefaultRestConfig(kubeClient, "", func(config *rest.Config) {
		config.QPS = 20
		config.Burst = 40
	})
	if err != nil {
		return nil, err
	}
	kc, err := kubelib.NewExtendedClient(kubelib.NewClientConfigForRestConfig(kubeRestConfig), "")
	if err != nil {
		return nil, err
	}
	c, err := crdclient.New(kc, "default", "cluster.local")
	if err != nil {
		return nil, err
	}

	schemas := collections.Pilot.All()
	for _, schema := range schemas {
		log.Infof("jianfeih schema %v", schema)
		c.RegisterEventHandler(schema.Resource().GroupVersionKind(), func(
			old config.Config, new config.Config, e model.Event) {
			log.Infof("jianfeih debug the event handler, event %v, config %v\n", e, new)
		})
	}
	log.Infof("jianfeih register finished")

	// c.RegisterEventHandler(istiogvk.AuthorizationPolicy, func(
	// 	old config.Config, new config.Config, e model.Event) {
	// 	log.Infof("jianfeih debug the event handler, event %v, config %v\n", e, new)
	// })
	stopCh := make(chan struct{})
	// TODO: here is the issue, hasSync never return true. the handlers are not invoked.
	go c.Run(stopCh)
	for {
		if c.HasSynced() {
			break
		}
		time.Sleep(time.Second * 3)
	}
	return &Client{
		configStore: c,
	}, nil
}
