package model

import (
	"bytes"
	"html/template"
	"io/ioutil"
)

// Render the security information into a HTML page.
func RenderHTML() error {
	b, err := ioutil.ReadFile("report.html.tpl")
	if err != nil {
		return err
	}
	t, err := template.New("webpage").Parse(string(b))
	if err != nil {
		return err
	}
	data := make([]byte, 2048)
	bw := bytes.NewBuffer(data)
	err = t.Execute(bw, SecurityReport{
		ConfigWarnings: []string{"authz1", "auth2"},
		Vunerabilities: []CVEEntry{
			{
				DisclosureID: "ISTIO-2022-03-01-0004",
			},
		},
	})
	if err != nil {
		return err
	}
	// TODO: why it's not openable by vscode? binary file warnings?
	if err := ioutil.WriteFile("report.html", bw.Bytes(), 0664); err != nil {
		return err
	}
	return nil
}
