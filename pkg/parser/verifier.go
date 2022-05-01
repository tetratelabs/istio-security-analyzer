package parser

import (
	"fmt"
	"strings"

	networkingv1alpha3 "istio.io/api/networking/v1alpha3"
	istioconfig "istio.io/istio/pkg/config"
	"istio.io/pkg/log"
)

func scanGatewaysAndVirtualServices(collectionsGw, collectionsVS []*istioconfig.Config) []error {
	out := []error{}
	gateways := []gatewayMetadata{}
	for _, policy := range collectionsGw {
		gw, err := checkGatewaysForRelaxedHost(policy)
		if err != nil {
			out = append(out, err...)
		}
		if gw.relaxedHostGateway != "" {
			gateways = append(gateways, gw)
		}
	}
	var filteredGWs = []gatewayMetadata{}
	for _, policy := range collectionsGw {
		filteredGWs = append(filteredGWs, checkGW4HostsWithHigherTLS(policy, gateways)...)
	}
	err := check4VirtualServices(collectionsVS, filteredGWs)
	out = append(out, err...)
	return out
}

func checkGatewaysForRelaxedHost(c *istioconfig.Config) (gateway gatewayMetadata, errs []error) {
	if c == nil {
		return
	}
	gw, ok := c.Spec.(*networkingv1alpha3.Gateway)
	if !ok {
		log.Errorf("unable to convert to istio destination rule: ok: %v\n%v", ok, c.Spec)
		return
	}
	for _, srv := range gw.Servers {
		for _, host := range srv.Hosts {
			if strings.Contains(host, "*") && host != "*" {
				gateway.relaxedHostGateway = c.Meta.Name
				if splitedHosts := strings.Split(host, "*"); len(splitedHosts) > 1 {
					splitedHost := splitedHosts[1]
					gateway.hosts = append(gateway.hosts, hostMetadata{relaxedHost: splitedHost, tlsModeRelaxedHost: srv.GetTls().GetMode().String()})
				}
			}
		}

	}
	return gateway, nil
}

func checkGW4HostsWithHigherTLS(c *istioconfig.Config, gateway []gatewayMetadata) (gwMetadata []gatewayMetadata) {
	gtw, ok := c.Spec.(*networkingv1alpha3.Gateway)
	if !ok {
		log.Errorf("unable to convert to istio gateway ok:%v\n actualData:%v", ok, c.Spec)
		return
	}
	filtered := gatewayMetadata{}
	for _, srvr := range gtw.Servers {
		for _, host := range srvr.Hosts {
			for _, gw := range gateway {
				for _, h := range gw.hosts {
					if strings.Contains(host, h.relaxedHost) && strings.Compare(host, h.relaxedHost) != 0 {
						if networkingv1alpha3.ServerTLSSettings_TLSmode_value[srvr.GetTls().GetMode().String()] > networkingv1alpha3.ServerTLSSettings_TLSmode_value[h.tlsModeRelaxedHost] {
							filtered = gatewayMetadata{relaxedHostGateway: gw.relaxedHostGateway, problematicHostGateway: c.Name}
							filtered.hosts = append(filtered.hosts, hostMetadata{relaxedHost: h.relaxedHost, problematicHost: host, tlsModeProblematicHost: srvr.GetTls().GetMode().String(), tlsModeRelaxedHost: h.tlsModeRelaxedHost})
						}
					}
				}
			}
		}
	}
	gwMetadata = append(gwMetadata, filtered)
	return
}

func check4VirtualServices(collections []*istioconfig.Config, metaData []gatewayMetadata) []error {
	out := []error{}
	for _, policy := range collections {
		err := checkVirtualServicesV2(policy, metaData)
		if err != nil {
			out = append(out, err...)
		}
	}
	for _, gtwCnf := range metaData {
		for _, host := range gtwCnf.hosts {
			if !host.resolved {
				msg := fmt.Errorf("no virtual service configured for gateway %s, for host %s, which is creating problem in gateway:%s, to reject call for host %s", gtwCnf.relaxedHostGateway, host.relaxedHost, gtwCnf.problematicHostGateway, host.problematicHost)
				out = append(out, msg)
			}
		}
	}
	return out
}

func checkVirtualServicesV2(c *istioconfig.Config, gateways []gatewayMetadata) (err []error) {
	if c == nil {
		return nil
	}
	vs, ok := c.Spec.(*networkingv1alpha3.VirtualService)
	if !ok {
		log.Errorf("unable to convert to istio virtual services: ok: %v\n Actual Data :%v", ok, c.Spec)
		return nil
	}
	for _, vsgtw := range vs.Gateways {
		for index, gtw := range gateways {
			if strings.Compare(gtw.relaxedHostGateway, vsgtw) == 0 {
				for i, hst := range gtw.hosts {
					for _, host := range vs.Hosts {
						if strings.Compare(host, hst.problematicHost) == 0 {
							for _, htttp := range vs.Http {
								for _, match := range htttp.GetMatch() {
									if strings.Compare("/", match.Uri.GetPrefix()) == 0 {
										// gatewayMeta := gatewayMetadata{relaxedHostGateway: gtw.relaxedHostGateway, problematicHostGateway: gtw.problematicHostGateway, hosts: }
										gateways[index].hosts[i].resolved = true
										// configuredVS4GW = append(configuredVS4GW, gtw)
										// configuredVS4GW = append(configuredVS4GW, gatewayMetadata{ : gtw.gateway, hosts: []hostMetadata{{host: host, tlsMode: }} })
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return
}

//represents metadata of gateway
type gatewayMetadata struct {
	relaxedHostGateway     string
	problematicHostGateway string
	hosts                  []hostMetadata
}

// represents metadata of host declared in gateway configuration
type hostMetadata struct {
	relaxedHost            string
	problematicHost        string
	tlsModeRelaxedHost     string
	tlsModeProblematicHost string
	resolved               bool
}
