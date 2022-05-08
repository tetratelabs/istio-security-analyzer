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
	_ "embed"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
	yaml "gopkg.in/yaml.v2"
	"istio.io/pkg/log"
)

func BuildEntryInfoForTest() []CVEEntry {
	return []CVEEntry{
		{
			DisclosureID: "ISTIO-SECURITY-2022-FOO",
			Description:  "VERY IMPORTANT SEC report: FOO2022!",
			ImpactScore:  9.9,
			affectedReleases: []ReleaseRange{
				// TODO: build testing data by helper func.
				{
					RangeType: ParticularType,
					Particular: IstioRelease{
						Major: 7,
						Minor: 8,
					},
				},
				{
					RangeType: IntervalType,
					Start: IstioRelease{
						Major: 11,
						Minor: 0,
					},
					End: IstioRelease{
						Major: 11,
						Minor: 4,
					},
				},
			},
		},
		{
			DisclosureID: "ISTIO-SECURITY-2022-004",
			Description:  "Unauthenticated control plane denial of service attack due to stack exhaustion",
			ImpactScore:  7.5,
		},
		{
			DisclosureID: "ISTIO-SECURITY-2022-003",
			Description:  "Multiple CVEs related to istiod Denial of Service and Envoy",
			ImpactScore:  7.5,
		},
	}
}

func SaveDatabase(entries []CVEEntry, path string) error {
	y, err := yaml.Marshal(entries)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(path, y, 0644); err != nil {
		return fmt.Errorf("failed to save cve entries to file: %v", err)
	}
	return nil
}

func FetchIstioPage() ([]CVEEntry, error) {
	resp, err := http.Get("https://istio.io/latest/news/security/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	entries := []CVEEntry{}
	doc.Find(".security-grid table tbody tr").Each(func(i int, s *goquery.Selection) {
		entries = append(entries, CVEEntry{})
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
			switch j {
			case 0:
				e.DisclosureID = text
			case 1:
				// TODO: Filling date from scraped data.
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

// FindVunerabilities returns the relevant security disclosures that might the given Istio release.
func FindVunerabilities(version string) []*CVEEntry {
	out := []*CVEEntry{}
	ver, err := istioReleaseFromString(version)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse version %v", version))
	}
	cves := []CVEEntry{}
	if err := yaml.Unmarshal([]byte(cveDatabaseYAML), &cves); err != nil {
		panic(fmt.Sprintf("Failed to parse cve database: %v", err))
	}
	for ind, c := range cves {
		for _, rangeStr := range c.ReleaseRanges {
			releaseRange, e := IstioReleaseRangeFromString(rangeStr)
			if e != nil {
				panic(fmt.Sprintf("failed to parse the release range, disclosure ID %v, range str %v", c.DisclosureID, rangeStr))
			}
			// We use index of the slice to ensure changing the actual slice element.
			cves[ind].affectedReleases = append(cves[ind].affectedReleases, releaseRange)
		}
	}
	for ind, entry := range cves {
		cves[ind].URL = fmt.Sprintf("https://istio.io/latest/news/security/%v", strings.ToLower(entry.DisclosureID))
		for _, s := range entry.affectedReleases {
			if s.Include(ver) {
				out = append(out, &cves[ind])
				break
			}
		}
	}
	return out
}
