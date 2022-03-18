package cve

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/PuerkitoBio/goquery"
	"github.com/incfly/gotmpl/model"
	yaml "gopkg.in/yaml.v2"
	"istio.io/pkg/log"
)

func buildImpactedReleases(releases ...string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, r := range releases {
		out[r] = struct{}{}
	}
	return out
}

func BuildEntryInfoForTest() []model.CVEEntry {
	return []model.CVEEntry{
		{
			DisclosureID: "ISTIO-SECURITY-2022-FOO",
			Description:  "VERY IMPORTANT SEC report: FOO2022!",
			ImpactScore:  9.9,
			AffectedReleases: []model.ReleaseRange{
				{
					RangeType: model.ParticularType,
					Particular: model.IstioRelease{
						Major: "1.7",
						Minor: "8",
					},
				},
				{
					RangeType: model.IntervalType,
					Start: model.IstioRelease{
						Major: "1.11",
						Minor: "0",
					},
					End: model.IstioRelease{
						Major: "1.11",
						Minor: "4",
					},
				},
			},
		},
		{
			DisclosureID: "ISTIO-SECURITY-2022-004",
			Description:  "Unauthenticated control plane denial of service attack due to stack exhaustion",
			ImpactScore:  7.5,
			// IstioReleases: buildImpactedReleases("1.11.1", "1.11.2", "1.11.3",
			// 	"1.11.4", "1.11.5", "1.11.6", "1.11.7"),
		},
		{
			DisclosureID: "ISTIO-SECURITY-2022-003",
			Description:  "Multiple CVEs related to istiod Denial of Service and Envoy",
			ImpactScore:  7.5,
			// IstioReleases: buildImpactedReleases("1.11.1", "1.11.2", "1.11.3",
			// 	"1.11.4", "1.11.5", "1.11.6"),
		},
	}
}

// LoadDatabase loads the information from a YAML format config.
func LoadDatabase(path string) ([]model.CVEEntry, error) {
	out := []model.CVEEntry{}
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read cve file: %v", err)
	}
	if err := yaml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("failed to parse cve file: %v", err)
	}
	return out, nil
}

func SaveDatabase(entries []model.CVEEntry, path string) error {
	y, err := yaml.Marshal(entries)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(path, y, 0644); err != nil {
		return fmt.Errorf("failed to save cve entries to file: %v", err)
	}
	return nil
}

// FindVunerabilities returns the relevant security disclosures that might the given Istio release.
func FindVunerabilities(version string) []string {
	out := []string{}
	// cves := BuildEntryInfoForTest()
	// for _, entry := range cves {
	// _, ok := entry.IstioReleases[version]
	// if ok {
	// 	out = append(out, entry.DisclosureID)
	// }
	// }
	return out
}

func FetchIstioPage() ([]model.CVEEntry, error) {
	resp, err := http.Get("https://istio.io/latest/news/security/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	entries := []model.CVEEntry{}
	doc.Find(".security-grid table tbody tr").Each(func(i int, s *goquery.Selection) {
		entries = append(entries, model.CVEEntry{})
		a := s.ChildrenFiltered("td")
		// NOTE: for affetcted release, Istio annoucement page uses a human readable format.
		// Parsing and convert text to an array of the versions is fragile.
		// Instead we can come up with a tool to update semi-automate:
		// Find a new entry, give the text.
		// Reminds the human, fill in the content. (may be a Web server form, or a CLI tool whichever easier.)
		// Update the database.
		// Next time seeing the entry, no new work requires.
		a.Each(func(j int, elm *goquery.Selection) {
			e := &entries[i]
			text := elm.Text()
			fmt.Printf("jianfeih element %v, %v\n", i, elm.Text())
			switch j {
			case 0:
				e.DisclosureID = text
			case 1:
				// TODO: solve date.
				// e.Date
			case 2:
				// Affected Release in text format.
			case 3:
				f, err := strconv.ParseFloat(text, 32)
				if err == nil {
					e.ImpactScore = float32(f)
				} else {
					log.Errorf("failed to parse the content(%v) to impact score.", text)
				}
			case 4:
				e.Description = text
			}
		})
	})
	return entries, nil
}
