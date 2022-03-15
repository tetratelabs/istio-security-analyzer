package cve

import (
	"fmt"
	"net/http"
	"time"

	"github.com/PuerkitoBio/goquery"
)

type EntryInfo struct {
	// DisclosureID uniquely identifies a single disclosure. For example, "ISTIO-SECURITY-2022-004".
	DisclosureID string
	// Description is a human-readable summary of the CVE.
	Description string
	// [0, 10].
	ImpactScore   float32
	Date          time.Time
	IstioReleases map[string]struct{}
}

func buildImpactedReleases(releases ...string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, r := range releases {
		out[r] = struct{}{}
	}
	return out
}

func TestOnlyEntryInfo() []EntryInfo {
	return []EntryInfo{
		{
			DisclosureID: "ISTIO-SECURITY-2022-004",
			Description: "	Unauthenticated control plane denial of service attack due to stack exhaustion",
			ImpactScore: 7.5,
			IstioReleases: buildImpactedReleases("1.11.1", "1.11.2", "1.11.3",
				"1.11.4", "1.11.5", "1.11.6", "1.11.7"),
		},
		{
			DisclosureID: "ISTIO-SECURITY-2022-003",
			Description:  "Multiple CVEs related to istiod Denial of Service and Envoy",
			ImpactScore:  7.5,
			IstioReleases: buildImpactedReleases("1.11.1", "1.11.2", "1.11.3",
				"1.11.4", "1.11.5", "1.11.6"),
		},
	}
}

func LoadDatabase(file string) ([]EntryInfo, error) {
	out := []EntryInfo{}
	return out, nil
}

func SaveDatabase(entries []EntryInfo, path string) {
}

// FindVunerabilities returns the relevant security disclosures that might the given Istio release.
func FindVunerabilities(version string) []string {
	out := []string{}
	cves := TestOnlyEntryInfo()
	for _, entry := range cves {
		_, ok := entry.IstioReleases[version]
		if ok {
			out = append(out, entry.DisclosureID)
		}
	}
	return out
}

func FetchIstioPage() error {
	resp, err := http.Get("https://istio.io/latest/news/security/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return err
	}

	doc.Find(".security-grid table tbody tr").Each(func(i int, s *goquery.Selection) {
		a := s.ChildrenFiltered("td")
		// NOTE: for affetcted release, Istio annoucement page uses a human readable format.
		// Parsing and convert text to an array of the versions is fragile.
		// Instead we can come up with a tool to update semi-automate:
		// Find a new entry, give the text.
		// Reminds the human, fill in the content. (may be a Web server form, or a CLI tool whichever easier.)
		// Update the database.
		// Next time seeing the entry, no new work requires.
		a.Each(func(i int, elm *goquery.Selection) {
			fmt.Printf("jianfeih element %v\n", elm.Text())
		})
	})
	return nil
}
