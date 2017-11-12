// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/coreos/ignition/internal/exec"
	"github.com/coreos/ignition/internal/exec/stages"
	_ "github.com/coreos/ignition/internal/exec/stages/disks"
	_ "github.com/coreos/ignition/internal/exec/stages/files"
	"github.com/coreos/ignition/internal/log"
	"github.com/coreos/ignition/internal/oem"
	"github.com/coreos/ignition/internal/profile"
	"github.com/coreos/ignition/internal/version"
)

func main() {
	flags := struct {
		clearCache   bool
		configCache  string
		fetchTimeout time.Duration
		oem          oem.Name
		profile      string
		root         string
		stage        stages.Name
		version      bool
		validate     string
	}{}

	flag.BoolVar(&flags.clearCache, "clear-cache", false, "clear any cached config")
	flag.StringVar(&flags.configCache, "config-cache", "/run/ignition.json", "where to cache the config")
	flag.DurationVar(&flags.fetchTimeout, "fetch-timeout", exec.DefaultFetchTimeout, "initial duration for which to wait for config")
	flag.Var(&flags.oem, "oem", fmt.Sprintf("current oem. %v", oem.Names()))
	flag.StringVar(&flags.profile, "profile", "", "path to OS-specific Ignition profile")
	flag.StringVar(&flags.root, "root", "/", "root of the filesystem")
	flag.Var(&flags.stage, "stage", fmt.Sprintf("execution stage. %v", stages.Names()))
	flag.BoolVar(&flags.version, "version", false, "print the version and exit")
	flag.StringVar(&flags.validate, "validate", "", "validate specified config then exit")

	flag.Parse()

	if flags.version {
		fmt.Printf("%s\n", version.String)
		return
	}

	if flags.validate != "" {
		report, err := exec.Validate(flags.validate)
		if len(report.Entries) != 0 {
			fmt.Println(report)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		if len(report.Entries) == 0 {
			// Just silently exit if everything passed without even warnings
			return
		}
		// Print this to be clear that despite any warnings the config is valid
		fmt.Println("Config is valid")
		return
	}

	if flags.oem == "" {
		fmt.Fprint(os.Stderr, "'--oem' must be provided\n")
		os.Exit(2)
	}

	if flags.stage == "" {
		fmt.Fprint(os.Stderr, "'--stage' must be provided\n")
		os.Exit(2)
	}

	logger := log.New()
	defer logger.Close()

	logger.Info(version.String)

	if flags.clearCache {
		if err := os.Remove(flags.configCache); err != nil {
			logger.Err("unable to clear cache: %v", err)
		}
	}

	prof, err := profile.New(flags.profile)
	if err != nil {
		logger.Crit("unable to parse profile: %v", err)
		os.Exit(1)
	}

	oemConfig := oem.MustGet(flags.oem.String())
	engine := exec.Engine{
		Root:         flags.root,
		FetchTimeout: flags.fetchTimeout,
		Logger:       &logger,
		ConfigCache:  flags.configCache,
		OEMConfig:    oemConfig,
		Profile:      prof,
	}

	if !engine.Run(flags.stage.String()) {
		os.Exit(1)
	}
}
