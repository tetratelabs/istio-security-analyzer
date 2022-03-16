package model

import "time"

type CVEEntry struct {
	// DisclosureID uniquely identifies a single disclosure. For example, "ISTIO-SECURITY-2022-004".
	DisclosureID string
	// Description is a human-readable summary of the CVE.
	Description string
	// [0, 10].
	ImpactScore float32
	Date        time.Time
	// TODO: think deeper on the appropriate way to represent the release set.
	// 1. Release vesion & release CVE can both happen at any time. Wording use "prior to 1.11".
	// TODO: consider make YAML format and the internal data structure different.
	// 1.7.8: {}, weird.
	IstioReleases map[string]struct{}
}

// SecurityReport contains a comprehensive summary of the scanning results.
type SecurityReport struct {
	IstioVersion   string
	Vunerabilities []CVEEntry
	ConfigWarnings []string
}
