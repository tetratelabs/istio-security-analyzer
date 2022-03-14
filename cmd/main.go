// Program scanner supports scanning Istio configuration and analzye CVE.
package main

// Plan of the record.
// Basic parser for Istio authoriation policy.
// - data structure, istio/client-go or something else? xcp does.
// - [ ] Check reports the total number of the policy scanned. (58 security policies, 32 networking policies.)
// - [ ] Consider to add more accurate error message tied to the field.

import (
	"fmt"

	"github.com/incfly/gotmpl/k8s"
	"github.com/incfly/gotmpl/parser"

	"github.com/spf13/cobra"
	"istio.io/pkg/log"
)

var (
	configDir      = "./"
	kubeConfigPath = "."

	loggingOptions log.Options

	scannerCmd = &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			if kubeConfigPath != "" {
				c, err := k8s.NewClient(kubeConfigPath)
				if err != nil {
					log.Fatalf("error %v", err)
				}
				stopCh := make(chan struct{})
				c.Run(stopCh)
				// start the watch loop for all istio config.

				// -- above two decide what kind of client to create. library identification.
				// istio controller OTS.

				// snapshot analyze.

				// report via log, or http server.
			}
			err := parser.CheckFileSystem(configDir)
			if err == nil {
				fmt.Println("success, no error found!")
				return
			}
			fmt.Printf("found warnings: %v\n", err)
		},
	}
)

func init() {
	flags := scannerCmd.Flags()

	flags.StringVarP(&configDir, "dir", "d", ".", "The input directory storing Istio YAML configuration.")
	flags.StringVarP(&kubeConfigPath, "config", "c", "", "The path to the kubeconfig of a cluster to be analyzed.")

	loggingOptions.SetOutputLevel("kube", log.ErrorLevel)
	loggingOptions.AttachCobraFlags(scannerCmd)
}

func main() {
	if err := scannerCmd.Execute(); err != nil {
		log.Fatalf("failed to run scanner: %v", err)
	}
}
