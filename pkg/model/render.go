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

package model

import (
	"bytes"
	_ "embed"
	"text/template"

	"github.com/tetratelabs/istio-security-scanner/pkg/parser"
	"istio.io/pkg/log"
)

const (
	reportTemplate = `==========================================
    Istio Security Report

Control Plane Version
- {{ .IstioVersion }}
{{if ne .DistrolessIssue ""}}
Distroless Warning
❗ {{ .DistrolessIssue }}
{{end}}

CVE Report
{{range .Vunerabilities}}❌ {{ .DisclosureID  }}  {{ .ImpactScore }}  {{ .URL }}
{{end}}

Config Report
We scanned {{.SecurityConfigCount}} security configurations, and {{.NetworkingConfigCount}} networking configurations.

{{range .ConfigWarnings}}❌ {{ . }}
{{end}}
==========================================
`
)

//go:embed database.yaml
var cveDatabaseYAML string

// RenderReport the security information into a HTML page.
func RenderReport(
	report IstioControlPlaneReport, configReport parser.ConfigScanningReport) string {
	t, err := template.New("webpage").Parse(string(reportTemplate))
	if err != nil {
		log.Fatalf("failed create render template: %v", err)
	}
	bw := bytes.NewBufferString("")
	warningMessage := []string{}
	for _, e := range configReport.Errors {
		warningMessage = append(warningMessage, e.Error())
	}
	distroMessage := ""
	if report.DistrolessIssue != nil {
		distroMessage = report.DistrolessIssue.Error()
	}
	params := securityReportParams{
		IstioVersion:    report.IstioVersion,
		ConfigWarnings:  warningMessage,
		DistrolessIssue: distroMessage,
		Vunerabilities:  FindVunerabilities(report.IstioVersion),
	}
	params.NetworkingConfigCount = configReport.CountByGroup[parser.NetworkingAPIGroup]
	params.SecurityConfigCount = configReport.CountByGroup[parser.SecurityAPIGroup]
	err = t.Execute(bw, params)
	if err != nil {
		log.Fatalf("failed to render template: %v", err)
	}
	return bw.String()
}
