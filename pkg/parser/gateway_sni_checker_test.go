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

import "testing"

func TestScanIstioConfigForRelaxedSNIHost(t *testing.T) {
	testCases := []struct {
		name                 string
		configFiles          []string
		wantErrors           []string
		securityConfigCount  int
		networkingConfigCount int
	}{
		{
			name: "relaxed sni host without vs reject",
			configFiles: []string{
				"admingateway.yaml",
				"gw-simple-tls.yaml",
			},
			wantErrors: []string{
				`no virtual service configured for gateway guestgateway, at host .example.com`,
			},
			securityConfigCount:  0,
			networkingConfigCount: 2,
		},
		{
			name: "relaxed sni host with vs reject",
			configFiles: []string{
				"admingateway.yaml",
				"gw-simple-tls.yaml",
				"vs-deny-relaxed-sni.yaml",
			},
			securityConfigCount:  0,
			networkingConfigCount: 3,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configs, err := loadTestConfigs(tc.configFiles...)
			if err != nil {
				t.Fatalf("failed to read config: %v", err)
			}
			report := ScanIstioConfig(configs)
			validateReport(t, report, tc.wantErrors, tc.securityConfigCount, tc.networkingConfigCount)
		})
	}
}
