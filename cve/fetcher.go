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
		// fmt.Printf("jianfeih debug goqueyr find %v\n", i)
		h, e := s.Html()
		fmt.Printf("jianfeih content %v, %v\n", h, e)
		// For each item found, get the title
		// title := s.Find("a").Text()
		// fmt.Printf("Review %d: %s\n", i, title)
	})
	return nil
}
