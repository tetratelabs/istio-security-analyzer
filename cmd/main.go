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

// The program supports scanning Istio configuration and analzye CVE.
package main

// Plan of the record.
// Basic parser for Istio authoriation policy.
// - [ ] Check reports the total number of the policy scanned. (58 security policies, 32 networking policies.)
// - [ ] Consider to add more accurate error message tied to the field.
// Analyze the Istio cluster.
// scanner --kube <kubeconfig-path>

import (
	"fmt"

	"github.com/spf13/cobra"
	"istio.io/pkg/log"

	"github.com/tetratelabs/istio-security-scanner/pkg/k8s"
)

var (
	kubeConfigPath = "."
	runOnce        = false
	version        = "dev"
	commit         = "dev"
	date           = "dev"
	loggingOptions log.Options

	flagVersion = false
	scannerCmd  = &cobra.Command{}

	analyzerCMD = &cobra.Command{
		Use:   "analyzer",
		Short: "parent command to use istio security analyzer features ",
	}
	meshCmd = &cobra.Command{
		Use:   "mesh",
		Short: "scan configurations and report security vulnerabilities",
		Run: func(cmd *cobra.Command, args []string) {
			if flagVersion {
				fmt.Printf("scanner %s (%s, %s)\n", version, commit, date)
				return
			}

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
	workloadCmd = &cobra.Command{
		Use:   "workload",
		Short: "scan workload and generate report",
		Run: func(cmd *cobra.Command, args []string) {
			// fetch workload specific details here
			fetchWorkloadInfo(&analyerOptions{
				KubeConfig: kubeConfigPath,
			}, args)
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

func fetchWorkloadInfo(options *analyerOptions, args []string) {
	c, err := k8s.NewClient(options.KubeConfig, runOnce)
	if err != nil {
		log.Fatalf("error getting kube client %v", err)
	}
	c.RunForWorkload(args)
}

func init() {
	flags := meshCmd.Flags()
	flags.BoolVar(&flagVersion, "version", false, "Show the version of scanner")
	flags.StringVarP(&kubeConfigPath, "config", "c", "~/.kube/config", "The path to the kubeconfig of a cluster to be analyzed.")
	flags.BoolVar(&runOnce, "once", true, "Whether running the scanning only one shot. If false, will continue in a loop")
	// By default if `--log_output_level` is not specified by users, we supress the output to make report clean.
	// Setting "default" is needed, otherwise setting "kube" alone does not work, due to issue possible
	// log package itself. That make log output level field as ",kube:none", no effect.
	loggingOptions.SetOutputLevel("default", log.InfoLevel)
	loggingOptions.SetOutputLevel("kube", log.NoneLevel)
	loggingOptions.AttachCobraFlags(meshCmd)
	analyzerCMD.AddCommand(meshCmd, workloadCmd)
	scannerCmd.AddCommand(analyzerCMD)
}

func main() {
	if err := scannerCmd.Execute(); err != nil {
		log.Fatalf("failed to run scanner: %v", err)
	}
}
