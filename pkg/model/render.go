package model

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"text/template"

	yaml "gopkg.in/yaml.v2"
	"istio.io/pkg/log"
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

// RenderReport the security information into a HTML page.
func RenderReport(istioVersion string, configIssues []error) string {
	t, err := template.New("webpage").Parse(string(reportTemplate))
	if err != nil {
		log.Fatalf("failed create render template: %v", err)
	}
	bw := bytes.NewBufferString("")
	warningMessage := []string{}
	for _, e := range configIssues {
		warningMessage = append(warningMessage, e.Error())
	}
	log.Infof("jianfeih found issues: %v", configIssues)
	err = t.Execute(bw, SecurityReport{
		IstioVersion:   istioVersion,
		ConfigWarnings: warningMessage,
		Vunerabilities: FindVunerabilities(istioVersion),
	})
	if err != nil {
		log.Fatalf("failed to render template: %v", err)
	}
	return bw.String()
}

// FindVunerabilities returns the relevant security disclosures that might the given Istio release.
func FindVunerabilities(version string) []*CVEEntry {
	out := []*CVEEntry{}
	err, ver := ParseRelease(version)
	if err != nil {
		log.Errorf("Failed to parse version %v", version)
		return out
	}
	cves, err := LoadDatabase("./database.yaml")
	if err != nil {
		log.Errorf("Failed to load database: %v", err)
		return out
	}
	for ind, entry := range cves {
		for _, s := range entry.AffectedReleases {
			if s.Include(ver) {
				out = append(out, &cves[ind])
				break
			}
		}
	}
	return out
}

// LoadDatabase loads the information from a YAML format config.
func LoadDatabase(path string) ([]CVEEntry, error) {
	out := []CVEEntry{}
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read cve file: %v", err)
	}
	if err := yaml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("failed to parse cve file: %v", err)
	}
	return out, nil
}
