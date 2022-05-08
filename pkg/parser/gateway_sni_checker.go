// Copyright 2022 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parser

import (
	"fmt"
	"strings"

	networkingv1alpha3 "istio.io/api/networking/v1alpha3"
	istioconfig "istio.io/istio/pkg/config"
	"istio.io/pkg/log"
)

// this function perform 3 checks :
// 1. scan gateways for relaxed sni hosts
// 2. check if any virtual service configured to reject call for those hosts
// 3. report error if any.
func scanGatewaysAndVirtualServices(input relaxed_sni_check) []error {
	if input.gateways == nil {
		return nil
	}
	out := []error{}
	gateways := []gatewayMetadata{}
	for _, gateway := range input.gateways[0] {
		gw, err := checkGatewaysForRelaxedSNIHost(gateway)
		if err != nil {
			out = append(out, err...)
		}
		if gw.relaxedHostGateway != "" {
			gateways = append(gateways, gw)
		}
	}
	var filteredGWs = []gatewayMetadata{}
	for _, gateway := range input.gateways[0] {
		filteredGWs = append(filteredGWs, checkGWHostsWithHigherTLS(gateway, gateways)...)
	}
	if len(filteredGWs) == 0 {
		return nil
	}

	if input.virtualServices != nil {
		err := checkVirtualServices(input.virtualServices[0], filteredGWs)
		if len(err) > 0 {
			out = append(out, err...)
		}
	} else {
		for _, gtw := range filteredGWs {
			for _, host := range gtw.hosts {
				msg := fmt.Errorf("no virtual service configured for gateway %s, for host %s, which is creating problem in gateway:%s, to reject call for host %s", gtw.relaxedHostGateway, host.relaxedHost, gtw.problematicHostGateway, host.problematicHost)
				out = append(out, msg)
			}
		}
	}
	return out
}

// check for hosts in gateway configs for relaxed sni hosts
func checkGatewaysForRelaxedSNIHost(c *istioconfig.Config) (gateway gatewayMetadata, errs []error) {
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

// this function iterates over gateways which are having relaxed sni hosts, checking TLS,
// if other gateways with relaxed sni host found with higher TLS, it returns that data.
func checkGWHostsWithHigherTLS(c *istioconfig.Config, gateway []gatewayMetadata) (gwMetadata []gatewayMetadata) {
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

// iterating over virtual services
func checkVirtualServices(collections []*istioconfig.Config, metaData []gatewayMetadata) []error {
	out := []error{}
	for _, policy := range collections {
		err := scanVirtualService(policy, metaData)
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

// this function scan virtual service configuration to reject relaxed sni host call.
// if found, marks that host in gateway as resolved.
func scanVirtualService(c *istioconfig.Config, gateways []gatewayMetadata) (err []error) {
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
							if t := isVSConfiguredToRejectSNIHost(vs); t {
								gateways[index].hosts[i].resolved = true
							}
						}
					}
				}
			}
		}
	}
	return
}

// iterates over http conf inside virtual service, returns
// true : if found configuration to reject relaxed sni host, else false
func isVSConfiguredToRejectSNIHost(vs *networkingv1alpha3.VirtualService) bool {
	for _, htttp := range vs.Http {
		for _, match := range htttp.GetMatch() {
			if strings.Compare("/", match.Uri.GetPrefix()) == 0 {
				return true
			}
		}
	}
	return false
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