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
	"fmt"

	"github.com/incfly/gotmpl/cve"
	"github.com/incfly/gotmpl/k8s"
	"github.com/incfly/gotmpl/parser"

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
	err := parser.CheckFileSystem(configDir)
	if err == nil {
		fmt.Println("success, no error found!")
		return
	}
	fmt.Printf("found warnings: %v\n", err)
	// Checking CVE based on current Istio version.
	ver, e := k8s.IstioVersion(options.KubeConfig)
	if e != nil {
		log.Errorf("failed to get Istio version: %v", err)
		return
	}
	out := cve.FindVunerabilities(ver)
	fmt.Printf("CVE report: %v\n", out)
}

func init() {
	flags := scannerCmd.Flags()

	flags.StringVarP(&configDir, "dir", "d", ".", "The input directory storing Istio YAML configuration.")
	flags.StringVarP(&kubeConfigPath, "config", "c", "", "The path to the kubeconfig of a cluster to be analyzed.")
	flags.StringVarP(&executeMode, "mode", "m", "cli", "The mode the scanner tool to run, valid options: cluster | cli.")

	loggingOptions.SetOutputLevel("kube", log.ErrorLevel)
	loggingOptions.AttachCobraFlags(scannerCmd)
}

func main() {
	if err := scannerCmd.Execute(); err != nil {
		log.Fatalf("failed to run scanner: %v", err)
	}
}
