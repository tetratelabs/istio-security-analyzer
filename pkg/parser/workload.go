package parser

import (
	"encoding/json"
	"fmt"

	"istio.io/pkg/log"
	corev1 "k8s.io/api/core/v1"
)

// WorkloadReport contains the scanning report for workload
type WorkloadReport struct {
	Name           string            `json:"Name"`
	Cluster        string            `json:"Cluster"`
	CaptureMode    string            `json:"Capture_Mode"`
	ServiceAccount string            `json:"Service_Account"`
	Status         string            `json:"Status"`
	Labels         map[string]string `json:"Labels"`
}

// string function formats report in json format
// Note : need to design standard report format
func (report WorkloadReport) string() string {
	data, err := json.MarshalIndent(report, "", "")
	if err != nil {
		log.Errorf("unable to convert report : %v\n", err)
		return "Unexpected error while getting workload details"
	}

	return string(data)
}

// ExtractWorkloadDetails fetches workload specific details
func ExtractWorkloadDetails(pod *corev1.Pod) string {
	var report WorkloadReport
	report.Name = pod.Name
	report.Cluster = pod.ClusterName
	if pod.Spec.ServiceAccountName != "" {
		report.ServiceAccount = pod.Spec.ServiceAccountName
	} else {
		report.ServiceAccount = "default"
	}
	report.Labels = pod.Labels
	report.Status = string(pod.Status.Phase)
	report.CaptureMode = getCaptureModes(pod.Annotations)
	return report.string()
}

// this function parse annotations and look for excluded ports for capturing traffic
func getCaptureModes(anotation map[string]string) string {
	var excludePorts []string
	for key, value := range anotation {
		if (key == "excludeInboundPorts" || key == "excludeOutboundPorts") && value != "" {
			excludePorts = append(excludePorts, value)
		}
	}
	if len(excludePorts) == 2 {
		return fmt.Sprintf("All except %s and %s", excludePorts[0], excludePorts[1])
	} else if len(excludePorts) == 0 {
		return "All"
	} else {
		return fmt.Sprintf("All except %s", excludePorts[0])
	}
}
