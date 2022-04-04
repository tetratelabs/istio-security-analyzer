// Program scanner supports scanning Istio configuration and analzye CVE.
package main

// Plan of the record.
// Basic parser for Istio authoriation policy.
// - [ ] Check reports the total number of the policy scanned. (58 security policies, 32 networking policies.)
// - [ ] Consider to add more accurate error message tied to the field.

// CUJ: user experience.
// Analyze the local config only
// scanner # prints the ".", using default kubeconfig find the cve version.

// scanner --dir . # print the local dir.
// CVE default database, use official URL: gist.github.com for now.
// CVE db, using file system.
// scanner --cve-database ./path/to/db

// Analyze the Istio cluster.
// scanner --kube <kubeconfig-path>

import (
	"github.com/tetratelabs/istio-security-scanner/pkg/k8s"

	"github.com/spf13/cobra"
	"istio.io/pkg/log"
)

var (
	kubeConfigPath = "."
	runOnce        = false
	loggingOptions log.Options

	scannerCmd = &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			RunAll(&analyerOptions{
				KubeConfig: kubeConfigPath,
			})
		},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			// TODO(incfly): this seems returning an error if print out. Check why.
			_ = log.Configure(&loggingOptions)
			return nil
		},
	}
)

type analyerOptions struct {
	Dir             string
	KubeConfig      string
	CVEDatabaseURL  string
	CVEDatabasePath string
}

func RunAll(options *analyerOptions) {
	c, err := k8s.NewClient(options.KubeConfig, runOnce)
	if err != nil {
		log.Fatalf("error %v", err)
	}
	stopCh := make(chan struct{})
	c.Run(stopCh)
}

func init() {
	flags := scannerCmd.Flags()
	flags.StringVarP(&kubeConfigPath, "config", "c", "~/.kube/config", "The path to the kubeconfig of a cluster to be analyzed.")
	flags.BoolVar(&runOnce, "once", true, "Whether running the scanning only one shot. If false, will continue in a loop")
	loggingOptions.AttachCobraFlags(scannerCmd)
}

func main() {
	if err := scannerCmd.Execute(); err != nil {
		log.Fatalf("failed to run scanner: %v", err)
	}
}
