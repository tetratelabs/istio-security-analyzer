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

	"github.com/stretchr/testify/require"
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
			expectedReport: model.WorkloadReport{ServiceAccount: "default", Cluster: "test", PodID: "podname", ExcludeInboundPorts: []string{}, ExcludeOutboundPorts: []string{}},
		},
		{
			name:           "Service account check",
			configFile:     corev1.Pod{ObjectMeta: v1.ObjectMeta{ClusterName: "test", Name: "podname"}, Spec: corev1.PodSpec{ServiceAccountName: "testServiceAcc"}},
			expectedReport: model.WorkloadReport{ServiceAccount: "testServiceAcc", Cluster: "test", PodID: "podname", ExcludeInboundPorts: []string{}, ExcludeOutboundPorts: []string{}},
		},
		{
			name:           "Parse excluded ports from pod's annotation",
			configFile:     corev1.Pod{ObjectMeta: v1.ObjectMeta{Annotations: map[string]string{"traffic.sidecar.istio.io/excludeOutboundPorts": "1234, 5678", "traffic.sidecar.istio.io/excludeInboundPorts": "4321, 8765"}, ClusterName: "test"}},
			expectedReport: model.WorkloadReport{ExcludeInboundPorts: []string{"1234, 5678"}, ExcludeOutboundPorts: []string{"4321, 8765"}, ServiceAccount: "default", Cluster: "test"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualReport := workloadReportFromPod(&tc.configFile)
			require.Equal(t, tc.expectedReport.PodID, actualReport.PodID)
			require.Equal(t, tc.expectedReport.Cluster, actualReport.Cluster)
			require.Equal(t, tc.expectedReport.ServiceAccount, actualReport.ServiceAccount)
			require.Equal(t, tc.expectedReport.ExcludeInboundPorts, actualReport.ExcludeInboundPorts)
			require.Equal(t, tc.expectedReport.ExcludeOutboundPorts, actualReport.ExcludeOutboundPorts)
		})
	}

}
func TestExtractCommandArgs(t *testing.T) {
	testCases := []struct {
		name              string
		args              []string
		expectedError     error
		expectedNamespace string
		expectedPodID     string
	}{
		{
			name: "Extract command args, valid input",
			// args should be in form of <namespace>.<podID>, hence valid args
			args:              []string{"testNamespace.testPodID"},
			expectedError:     nil,
			expectedNamespace: "testNamespace",
			expectedPodID:     "testPodID",
		},
		{
			name:              "Extract command args, invalid input. ie. invalid args",
			args:              []string{"invalid_args"},
			expectedError:     errInvalidWorkloadArgs,
			expectedNamespace: "",
			expectedPodID:     "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ns, podID, err := extractCommandArgs(tc.args)
			require.Equal(t, tc.expectedError, err)
			require.Equal(t, tc.expectedNamespace, ns)
			require.Equal(t, tc.expectedPodID, podID)
		})
	}
}
