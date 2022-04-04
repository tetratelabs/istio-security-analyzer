// Program scanner supports scanning Istio configuration and analzye CVE.
package main

// Plan of the record.
// Basic parser for Istio authoriation policy.
// - data structure, istio/client-go or something else? xcp does.
// - [ ] Check reports the total number of the policy scanned. (58 security policies, 32 networking policies.)
// - [ ] Consider to add more accurate error message tied to the field.

// CUJ: user experience.
// Analyze the local config only
// scanner # prints the ".", using default kubeconfig find the cve version.

// scanner --dir . # print the local dir.

// scanner --mode <cluster|cli> # only in cluster we ignore the dir value.

// CVE default database, use official URL: gist.github.com for now.

// CVE db, using file system.
// scanner --cve-database ./path/to/db

// Analyze the Istio cluster.
// scanner --kube <kubeconfig-path>

// Usage.
//  ./out/scanner --config $HOME/.kube/config  --mode cluster
// ./out/scanner --config $HOME/.kube/config --dir ./parser

import (
	"github.com/tetratelabs/istio-security-scanner/pkg/k8s"

	"github.com/spf13/cobra"
	"istio.io/pkg/log"
)

var (
	configDir      = "./"
	kubeConfigPath = "."
	executeMode    = "mode"

	loggingOptions log.Options

	scannerCmd = &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			RunAll(&Option{
				KubeConfig: kubeConfigPath,
				ExecMode:   executeMode,
			})
		},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			// TODO(incfly): this seems returning an error if print out. Check why.
			_ = log.Configure(&loggingOptions)
			return nil
		},
	}
)

// TODO(incfly): move to the right package may not in main.go.
type Option struct {
	ExecMode        string
	Dir             string
	KubeConfig      string
	CVEDatabaseURL  string
	CVEDatabasePath string
}

func RunAll(options *Option) {
	// TODO(incfly): cluster mode bug. start with authz config, create dr, not print out in the
	// following HTTP request.
	if options.ExecMode == "cluster" {
		c, err := k8s.NewClient(options.KubeConfig)
		if err != nil {
			log.Fatalf("error %v", err)
		}
		stopCh := make(chan struct{})
		c.Run(stopCh)
		return
	}
	// CLI mode.
	// configIssues := parser.CheckFileSystem(configDir)
	// ver, err := k8s.IstioVersion(options.KubeConfig)
	// if err != nil {
	// 	log.Fatalf("failed to get Istio version: %v", configIssues)
	// }
	// report := model.RenderReport(
	// 	ver,
	// 	configIssues,
	// )
	// log.Info(report)
}

func init() {
	flags := scannerCmd.Flags()

	flags.StringVarP(&configDir, "dir", "d", ".", "The input directory storing Istio YAML configuration.")
	flags.StringVarP(&kubeConfigPath, "config", "c", "", "The path to the kubeconfig of a cluster to be analyzed.")
	flags.StringVarP(&executeMode, "mode", "m", "cluster", "The mode the scanner tool to run, valid options: cluster | cli.")
	loggingOptions.AttachCobraFlags(scannerCmd)
}

func main() {
	if err := scannerCmd.Execute(); err != nil {
		log.Fatalf("failed to run scanner: %v", err)
	}
}
