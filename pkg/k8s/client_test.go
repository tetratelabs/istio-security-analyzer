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

package k8s

import (
	"testing"

	"istio.io/istio/pkg/config/constants"
	corev1 "k8s.io/api/core/v1"
)

func TestCheckJWTPolicies(t *testing.T) {
	tempGetCMFunc := getK8SConfigMap
	// checking with jwt policy configured as third party
	getK8SConfigMapFunc = mockGetK8SConfigMapThirdParty

	err := checkJWTPolicy(constants.IstioSystemNamespace, nil)
	if err != nil {
		t.Fatalf("expected nil error but got %v", err)
	}

	// checking with jwt policy configured as non-third party configuration
	getK8SConfigMapFunc = mockGetK8SConfigMapJWTDefault
	err = checkJWTPolicy(constants.IstioSystemNamespace, nil)
	if err == nil {
		t.Fatalf("expected error for less secure jwt policy configuration but got nil")
	}

	getK8SConfigMapFunc = mockGetK8SConfigMapJWTNotConfigured
	err = checkJWTPolicy(constants.IstioSystemNamespace, nil)
	if err != nil {
		t.Fatalf("should indicate no jwt policy configured")
	}

	getK8SConfigMapFunc = tempGetCMFunc

}

// mock function of getK8SConfigMapFunc, returns K8S config map with valid jwt policy configuration
func mockGetK8SConfigMapThirdParty(client *Client, cmName string) (*corev1.ConfigMap, error) {
	configMapMockData := map[string]string{
		"values": `{"global": {"jwtPolicy": "third-party-jwt"}}`,
	}
	return &corev1.ConfigMap{Data: configMapMockData}, nil
}

// mock function of getK8SConfigMapFunc, returns K8S config map with less secure jwt policy configuration
func mockGetK8SConfigMapJWTDefault(client *Client, cmName string) (*corev1.ConfigMap, error) {
	configMapMockData := map[string]string{
		"values": `{"global": {"jwtPolicy": "default"}}`,
	}
	return &corev1.ConfigMap{Data: configMapMockData}, nil
}

// mock function of getK8SConfigMapFunc, returns config map without jwt policy configuration
func mockGetK8SConfigMapJWTNotConfigured(client *Client, cmName string) (*corev1.ConfigMap, error) {
	configMapMockData := map[string]string{
		"values": `{"global": {"caName": ""}}`,
	}
	return &corev1.ConfigMap{Data: configMapMockData}, nil
}
