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
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	istioConfig "istio.io/istio/pkg/config"
)

func loadTestConfigs(files ...string) ([]*istioConfig.Config, error) {
	configObjects := make([]*istioConfig.Config, 0)
	for _, inputTmpl := range files {
		yamlBytes, err := ioutil.ReadFile("testdata/" + inputTmpl)
		if err != nil {
			return nil, fmt.Errorf("unable to read file %s: %w", inputTmpl, err)
		}
		yamlStr := string(yamlBytes)
		kubeYaml := yamlStr
		cfgs, err := decodeConfigYAML(kubeYaml)
		if err != nil {
			return nil, fmt.Errorf("unable to decode kubernetes configs in file %s: %w", inputTmpl, err)
		}
		for _, cfg := range cfgs {
			cobjCopy := cfg.DeepCopy()
			configObjects = append(configObjects, &cobjCopy)
		}
	}
	return configObjects, nil
}

func validateReport(t *testing.T, report ConfigScanningReport, wantErrors []string,
	securityConfigCount int, networkingConfigCount int) {
	t.Helper()
	gotSecurity := report.CountByGroup[SecurityAPIGroup]
	require.Equal(t, securityConfigCount, gotSecurity)
	gotNetworkingCount := report.CountByGroup[NetworkingAPIGroup]
	require.Equal(t, networkingConfigCount, gotNetworkingCount)
	for _, want := range wantErrors {
		found := false
		for _, actual := range report.Errors {
			if strings.Contains(actual.Error(), want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("failed to find error contains substring '%v'\ngot errors %v\n", want, report.Errors)
		}
	}
}

func TestScanIstioConfig(t *testing.T) {
	testCases := []struct {
		name                 string
		configFiles          []string
		wantErrors           []string
		securityConfigCount  int
		networkingConfigCount int
	}{
		{
			name: "All",
			configFiles: []string{
				"authz.yaml",
				"authz-allow-negative.yaml",
				"dr-tls.yaml",
				"gateway-broad-host.yaml",
			},
			wantErrors: []string{
				`authorization policy: found negative matches`,
				`destination rule: either caCertificates or subjectAltNames is not set`,
				`host "*" is overly broad`,
			},
			securityConfigCount:  2,
			networkingConfigCount: 3,
		},
		{
			name: "SingleAuthz",
			configFiles: []string{
				"authz.yaml",
			},
			wantErrors:           []string{},
			securityConfigCount:  1,
			networkingConfigCount: 0,
		},
		{
			name:                 "Nothing",
			configFiles:          []string{},
			securityConfigCount:  0,
			networkingConfigCount: 0,
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
