package model

import (
	"bytes"
	"fmt"
	"net/http"
	"text/template"
)

const (
	reportTemplate = `Istio Security Scanning Report

Config Warnings
{{range .ConfigWarnings}}- {{ .  }}
{{end}}

CVE Report
{{range .Vunerabilities}}- {{ .DisclosureID  }}
{{end}}
`
)

func hello(w http.ResponseWriter, req *http.Request) {
	report, err := RenderReport()
	if err != nil {
		_, _ = w.Write([]byte(fmt.Sprintf("failed to prepare the report: %v", err)))
		return
	}
	_, _ = w.Write([]byte(report))
}

// Render the security information into a HTML page.
func RenderReport() (string, error) {
	t, err := template.New("webpage").Parse(string(reportTemplate))
	if err != nil {
		return "", err
	}
	bw := bytes.NewBufferString("")
	err = t.Execute(bw, SecurityReport{
		ConfigWarnings: []string{"authz1", "auth2"},
		Vunerabilities: []CVEEntry{
			{
				DisclosureID: "ISTIO-2022-03-01-0004",
			},
		},
	})
	if err != nil {
		return "", err
	}
	return bw.String(), nil
}

// TODO(here): proper server structure.
func StartAll() {
	http.HandleFunc("/", hello)
	http.ListenAndServe(":8080", nil)
}
