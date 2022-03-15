package cve

import (
	"fmt"
	"net/http"

	"github.com/PuerkitoBio/goquery"
)

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
