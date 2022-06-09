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

// HandleWorkloadRequests scans workload related configurations and generate report
func (c *Client) HandleWorkloadRequests(args []string) {
	report, err := c.fetchWorkloadDetails(args)
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

func (c *Client) fetchWorkloadDetails(args []string) (model.WorkloadReport, error) {
	if len(args) == 0 {
		return model.WorkloadReport{}, errors.New("information about workload not provided")
	}
	// first arg should be containing information about pod and namespace. i.e. <workload-id>.namespace
	workloadInfo := strings.Split(args[0], ".")
	if len(workloadInfo) != 2 {
		msg := "unable to parse provided args"
		log.Errorf(msg+"%v\n", args)
		return model.WorkloadReport{}, errors.New(msg)
	}
	pod, err := c.kubeClient.CoreV1().Pods(workloadInfo[1]).Get(context.Background(), workloadInfo[0], meta_v1.GetOptions{})
	if err != nil {
		log.Errorf("Unable to fetch workload:%s : %v\n", workloadInfo[0], err)
		return model.WorkloadReport{}, err
	}
	return workloadReportFromPod(pod), nil
}

// workloadReportFromPod fetches workload specific details
func workloadReportFromPod(pod *corev1.Pod) model.WorkloadReport {
	var report model.WorkloadReport
	report.Name = pod.Name
	report.Cluster = pod.ClusterName
	if pod.Spec.ServiceAccountName != "" {
		report.ServiceAccount = pod.Spec.ServiceAccountName
	} else {
		report.ServiceAccount = "default"
	}
	getGetExcludedPorts(pod.Annotations, &report)
	return report
}

// this function parse annotations and look for excluded ports for capturing traffic
func getGetExcludedPorts(anotation map[string]string, report *model.WorkloadReport) {
	for key, value := range anotation {
		if key == "excludeInboundPorts" && value != "" {
			report.ExcludeInboundPorts = append(report.ExcludeInboundPorts, value)
		} else if key == "excludeOutboundPorts" && value != "" {
			report.ExcludeOutboundPorts = append(report.ExcludeOutboundPorts, value)
		}
	}
}
