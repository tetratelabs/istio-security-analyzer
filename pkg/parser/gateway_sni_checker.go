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

// this function checks: whether gateway has relaxed sni configuration and if so, do we have the virtual service
// to prevent insecure access.
func scanGatewayRelaxedSniHost(inputConfig []configCollection) []error {
	var gatewayConfigs configCollection
	var vsConfigs configCollection
	if len(inputConfig) > 0 {
		gatewayConfigs = inputConfig[0]
	}
	out := []error{}
	gateways := []gatewayRelaxedSniCheckInfo{}
	for _, gateway := range gatewayConfigs {
		gw := findGatewayHostsForRelaxedSniHost(gateway)
		if gw.relaxedHostGateway != "" {
			gateways = append(gateways, gw)
		}
	}
	if len(gateways) == 0 {
		return nil
	}
	var filteredGWs = []gatewayRelaxedSniCheckInfo{}
	for _, gateway := range gatewayConfigs {
		filteredGWs = append(filteredGWs, checkGWHostsWithHigherTLS(gateway, gateways)...)
	}
	if len(filteredGWs) == 0 {
		return nil
	}

	if len(inputConfig) > 1 {
		vsConfigs = inputConfig[1]
	}

	if len(vsConfigs) > 0 {
		errs := hasVSRejectRelaxedTLSMode(vsConfigs, filteredGWs)
		if len(errs) > 0 {
			out = append(out, errs...)
		}
	} else {
		for _, gtw := range filteredGWs {
			for _, host := range gtw.hosts {
				msg := fmt.Errorf("no virtual service configured for gateway %s, at host %s, which is creating problem in gateway:%s, to reject call for host %s", gtw.relaxedHostGateway, host.relaxedHost, gtw.privilegedHostGateway, host.privilegedHost)
				out = append(out, msg)
			}
		}
	}
	return out
}

// check for hosts in gateway configs for relaxed sni hosts
func findGatewayHostsForRelaxedSniHost(c *istioconfig.Config) (gateway gatewayRelaxedSniCheckInfo) {
	if c == nil {
		return
	}
	gw, ok := c.Spec.(*networkingv1alpha3.Gateway)
	if !ok {
		log.Errorf("Unable to convert to istio gateway : ok: %v\n%v", ok, c.Spec)
		return
	}
	for _, srv := range gw.Servers {
		for _, host := range srv.Hosts {
			if strings.Contains(host, "*") && host != "*" {
				gateway.relaxedHostGateway = c.Meta.Name
				// We are checking the wildcard gateway host. This typically is as format of "*.example.com". therefore we are splitting by "*" and take the second element of the slice as the value
				if splitedHosts := strings.Split(host, "*"); len(splitedHosts) > 1 {
					gateway.hosts = append(gateway.hosts, gatewayRelaxedSniHostInfo{relaxedHost: splitedHosts[1], tlsModeRelaxedHost: srv.GetTls().GetMode().String()})
				}
			}
		}

	}
	return gateway
}

// this function iterates over gateways which are having relaxed sni hosts, checking TLS,
// if other gateways with relaxed sni host found with higher TLS, it returns that data.
func checkGWHostsWithHigherTLS(c *istioconfig.Config, gateway []gatewayRelaxedSniCheckInfo) (gwMetadata []gatewayRelaxedSniCheckInfo) {
	gtw, ok := c.Spec.(*networkingv1alpha3.Gateway)
	if !ok {
		log.Errorf("Unable to convert to istio gateway ok:%v\n actualData:%v", ok, c.Spec)
		return
	}
	filtered := gatewayRelaxedSniCheckInfo{}
	for _, srvr := range gtw.Servers {
		for _, host := range srvr.Hosts {
			for _, gw := range gateway {
				for _, h := range gw.hosts {
					// checking whether host(s) configured in the gateway contains relaxed SNI host suffix. for example *.example.com
					// is relaxed SNI host, so this check will look for host containing relaxed SNI host inside it. i.e abc.example.com
					if strings.Contains(host, h.relaxedHost) && strings.Compare(host, h.relaxedHost) != 0 {
						// Checking whether the privileged host configured with higher TLS than relaxed SNI host,
						// 1. Yes, then that host will be checked with whether a virtual service is configured to reject call for privileged host.
						if gatewayTLSModeLessSecure(srvr.GetTls().GetMode().String(), h.tlsModeRelaxedHost) {
							filtered = gatewayRelaxedSniCheckInfo{relaxedHostGateway: gw.relaxedHostGateway, privilegedHostGateway: c.Name}
							gatewayRelaxedSniHostInfo := gatewayRelaxedSniHostInfo{relaxedHost: h.relaxedHost, privilegedHost: host, tlsModePrivilegedHost: srvr.GetTls().GetMode().String(), tlsModeRelaxedHost: h.tlsModeRelaxedHost}
							filtered.hosts = append(filtered.hosts, gatewayRelaxedSniHostInfo)
						}
					}
				}
			}
		}
	}
	gwMetadata = append(gwMetadata, filtered)
	return
}

func gatewayTLSModeLessSecure(tls1, tls2 string) bool {
	return networkingv1alpha3.ServerTLSSettings_TLSmode_value[tls1] > networkingv1alpha3.ServerTLSSettings_TLSmode_value[tls2]
}

// iterating over virtual services
func hasVSRejectRelaxedTLSMode(collections []*istioconfig.Config, metaData []gatewayRelaxedSniCheckInfo) []error {
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
				msg := fmt.Errorf("no virtual service configured for gateway %q, at host %q, which is creating problem in gateway: %q, to reject call for host %q", gtwCnf.relaxedHostGateway, host.relaxedHost, gtwCnf.privilegedHostGateway, host.privilegedHost)
				out = append(out, msg)
			}
		}
	}
	return out
}

// this function scan virtual service configuration to reject relaxed sni host call. if found, marks that host in gateway as resolved.
func scanVirtualService(c *istioconfig.Config, gateways []gatewayRelaxedSniCheckInfo) (err []error) {
	if c == nil {
		return nil
	}
	vs, ok := c.Spec.(*networkingv1alpha3.VirtualService)
	if !ok {
		log.Errorf("Unable to convert to istio virtual services: ok: %v\n Actual Data :%v", ok, c.Spec)
		return nil
	}
	for _, vsgtw := range vs.Gateways {
		for index, gtw := range gateways {
			// checking whether virtual service is associated with the gateway having relaxed SNI host
			if strings.Compare(gtw.relaxedHostGateway, vsgtw) == 0 {
				for i, hst := range gtw.hosts {
					for _, host := range vs.Hosts {
						if strings.Compare(host, hst.privilegedHost) == 0 {
							// checking whether any virtual service is configured to reject call for privileged host with higher TLS.
							if t := isVSRejectRelaxedTLS(vs); t {
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

// iterates over http conf inside virtual service, returns true when found configuration to reject relaxed sni host
func isVSRejectRelaxedTLS(vs *networkingv1alpha3.VirtualService) bool {
	for _, htttp := range vs.Http {
		for _, match := range htttp.GetMatch() {
			if strings.Compare("/", match.Uri.GetPrefix()) == 0 {
				return true
			}
		}
	}
	return false
}

//represents metadata of gateway for relaxed sni hosts
type gatewayRelaxedSniCheckInfo struct {
	relaxedHostGateway    string
	privilegedHostGateway string
	hosts                 []gatewayRelaxedSniHostInfo
}

// clubs attributes to process relaxed and privileged hosts
type gatewayRelaxedSniHostInfo struct {
	relaxedHost           string
	privilegedHost        string
	tlsModeRelaxedHost    string
	tlsModePrivilegedHost string
	resolved              bool
}
