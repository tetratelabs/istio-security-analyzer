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
	"context"
	"encoding/json"
	"errors"
	"strings"

	"istio.io/pkg/log"
	corev1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tetratelabs/istio-security-scanner/pkg/model"
)

var (
	errInvalidWorkloadArgs = errors.New("unbale to parse args")
)

// GenerateWorkloadReport scans workload related configurations and generate report
func (c *Client) GenerateWorkloadReport(args []string) {
	podID, ns, err := extractCommandArgs(args)
	if err != nil {
		log.Errorf("unable to process command args : %v\n", err)
		return
	}
	report, err := c.fetchWorkloadDetails(podID, ns)
	if err != nil {
		log.Errorf("Unable to fetch workload details")
		return
	}
	data, err := json.MarshalIndent(report, "", "\t")
	if err != nil {
		log.Errorf("Unable to process workload data : %v\n", err)
		return
	}
	log.Infof("Report\n%s", data)
}

func extractCommandArgs(args []string) (string, string, error) {
	// first arg should be containing information about pod and namespace. i.e. <workload-id>.namespace
	workloadInfo := strings.Split(args[0], ".")
	if len(workloadInfo) != 2 {
		log.Errorf("%v\n", args)
		return "", "", errInvalidWorkloadArgs
	}
	return workloadInfo[0], workloadInfo[1], nil
}

func (c *Client) fetchWorkloadDetails(podID, ns string) (model.WorkloadReport, error) {
	pod, err := c.kubeClient.CoreV1().Pods(ns).Get(context.Background(), podID, meta_v1.GetOptions{})
	if err != nil {
		log.Errorf("Unable to fetch pod details:%s : %v\n", podID, err)
		return model.WorkloadReport{}, err
	}
	return workloadReportFromPod(pod), nil
}

// workloadReportFromPod fetches workload specific details
func workloadReportFromPod(pod *corev1.Pod) model.WorkloadReport {
	var report = model.WorkloadReport{}
	report.PodID = pod.Name
	report.Cluster = pod.ClusterName
	if pod.Spec.ServiceAccountName != "" {
		report.ServiceAccount = pod.Spec.ServiceAccountName
	} else {
		report.ServiceAccount = "default"
	}
	populateExcludedPorts(pod.Annotations, &report)
	return report
}

// this function parse annotations and look for excluded ports for capturing traffic
func populateExcludedPorts(anotation map[string]string, report *model.WorkloadReport) {
	log.Error(anotation)
	for key, value := range anotation {
		if key == "traffic.sidecar.istio.io/excludeOutboundPorts" && value != "" {
			report.ExcludeInboundPorts = append(report.ExcludeInboundPorts, value)
		} else if key == "traffic.sidecar.istio.io/excludeInboundPorts" && value != "" {
			report.ExcludeOutboundPorts = append(report.ExcludeOutboundPorts, value)
		}
	}
	if report.ExcludeInboundPorts == nil {
		report.ExcludeInboundPorts = []string{}
	}
	if report.ExcludeOutboundPorts == nil {
		report.ExcludeOutboundPorts = []string{}
	}
}
