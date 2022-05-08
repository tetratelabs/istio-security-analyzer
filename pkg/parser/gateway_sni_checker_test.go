package parser

import "testing"

func TestScanIstioConfigForRelaxedSNIHost(t *testing.T) {
	testCases := []struct {
		name                 string
		configFiles          []string
		wantErrors           []string
		securityConfigCount  int
		networkingConigCount int
	}{
		{
			name: "relaxed-sni-host-check-issue",
			configFiles: []string{
				"admingateway.yaml",
				"gw-simple-tls.yaml",
			},
			wantErrors: []string{
				`no virtual service configured for gateway`,
			},
			securityConfigCount:  1,
			networkingConigCount: 2,
		},
		{
			name: "relaxed-sni-host-check-solution",
			configFiles: []string{
				"admingateway.yaml",
				"gw-simple-tls.yaml",
				"vs-deny-relaxed-sni.yaml",
			},
			securityConfigCount:  0,
			networkingConigCount: 3,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configs, err := loadTestConfigs(tc.configFiles...)
			if err != nil {
				t.Fatalf("failed to read config: %v", err)
			}
			report := ScanIstioConfig(configs)
			validateReport(t, report, tc.wantErrors, tc.securityConfigCount, tc.networkingConigCount)
		})
	}
}
