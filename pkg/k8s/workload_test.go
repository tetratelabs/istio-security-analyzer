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

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tetratelabs/istio-security-scanner/pkg/model"
)

func TestParseWorkload(t *testing.T) {
	testCases := []struct {
		name           string
		configFile     corev1.Pod
		expectedReport model.WorkloadReport
	}{
		{
			name:           "Parse basic info from pod",
			configFile:     corev1.Pod{ObjectMeta: v1.ObjectMeta{ClusterName: "test", Name: "podname"}},
			expectedReport: model.WorkloadReport{ServiceAccount: "default", Cluster: "test", Name: "podname"},
		},
		{
			name:           "Service account check",
			configFile:     corev1.Pod{ObjectMeta: v1.ObjectMeta{ClusterName: "test", Name: "podname"}, Spec: corev1.PodSpec{ServiceAccountName: "testServiceAcc"}},
			expectedReport: model.WorkloadReport{ServiceAccount: "testServiceAcc", Cluster: "test", Name: "podname"},
		},
		{
			name:           "Parse excluded ports from pod's annotation",
			configFile:     corev1.Pod{ObjectMeta: v1.ObjectMeta{Annotations: map[string]string{"excludeOutboundPorts": "1234, 5678", "excludeInboundPorts": "4321, 8765"}, ClusterName: "test"}},
			expectedReport: model.WorkloadReport{ExcludeOutboundPorts: []string{"1234, 5678"}, ExcludeInboundPorts: []string{"4321, 8765"}, ServiceAccount: "default", Cluster: "test"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualReport := workloadReportFromPod(&tc.configFile)
			if actualReport.Name != tc.expectedReport.Name {
				t.Fatalf("expected workload name %s in report but got %s", tc.expectedReport.Name, actualReport.Name)
			} else if actualReport.Cluster != tc.expectedReport.Cluster {
				t.Fatalf("expected cluster name %s in report but got %s", tc.expectedReport.Cluster, actualReport.Cluster)
			} else if len(actualReport.ExcludeOutboundPorts) != len(tc.expectedReport.ExcludeOutboundPorts) {
				t.Fatalf("expected excluded outbound ports %s in report but got %s", tc.expectedReport.ExcludeOutboundPorts, actualReport.ExcludeOutboundPorts)
			} else if len(actualReport.ExcludeInboundPorts) != len(tc.expectedReport.ExcludeInboundPorts) {
				t.Fatalf("expected excluded inbound ports %s in report but got %s", tc.expectedReport.ExcludeInboundPorts, actualReport.ExcludeInboundPorts)
			} else if actualReport.ServiceAccount != tc.expectedReport.ServiceAccount {
				t.Fatalf("expected Service account name %s in report but got %s", tc.expectedReport.ServiceAccount, actualReport.ServiceAccount)
			}
		})
	}
}
