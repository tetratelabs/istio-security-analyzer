package model

import (
	"bytes"
	_ "embed"
	"text/template"

	"istio.io/pkg/log"
)

const (
	reportTemplate = `==========================================
    Istio Security Scanning Report

Control Plane Version
- {{ .IstioVersion }}
{{if ne .DistrolessIssue ""}}
Distroless Warning
❗ {{ .DistrolessIssue }}
{{end}}

CVE Report
{{range .Vunerabilities}}❌ {{ .DisclosureID  }}  {{ .ImpactScore }}  {{ .URL }}
{{end}}

Config Warnings
{{range .ConfigWarnings}}❌ {{ . }}
{{end}}
==========================================
`
)

//go:embed database.yaml
var cveDatabaseYAML string

// RenderReport the security information into a HTML page.
func RenderReport(report IstioControlPlaneReport, configIssues []error) string {
	t, err := template.New("webpage").Parse(string(reportTemplate))
	if err != nil {
		log.Fatalf("failed create render template: %v", err)
	}
	bw := bytes.NewBufferString("")
	warningMessage := []string{}
	for _, e := range configIssues {
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
	err = t.Execute(bw, params)
	if err != nil {
		log.Fatalf("failed to render template: %v", err)
	}
	return bw.String()
}
