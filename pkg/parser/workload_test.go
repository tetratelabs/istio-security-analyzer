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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseWorkload(t *testing.T) {
	testCases := []struct {
		name           string
		configFile     corev1.Pod
		reportMustHave []string
	}{
		{
			name:           "Parse annotation from pod details",
			configFile:     corev1.Pod{ObjectMeta: v1.ObjectMeta{Annotations: map[string]string{"excludeOutboundPorts": "1234"}, ClusterName: "test"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			reportMustHave: []string{"All except 1234", "test", "Running"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			details := ParseWorkloadDetails(&tc.configFile)
			for _, mustHaveStr := range tc.reportMustHave {
				if !strings.Contains(details, mustHaveStr) {
					t.Fatalf("final report must contain %v but not found", mustHaveStr)
				}
			}
		})
	}
}
