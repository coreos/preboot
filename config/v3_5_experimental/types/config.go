// Copyright 2020 Red Hat, Inc.
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

package types

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/coreos/ignition/v2/config/shared/errors"
	"github.com/coreos/ignition/v2/config/util"

	"github.com/coreos/go-semver/semver"
	"github.com/coreos/vcontext/path"
	"github.com/coreos/vcontext/report"
)

var (
	MaxVersion = semver.Version{
		Major:      3,
		Minor:      5,
		PreRelease: "experimental",
	}
)

var paths = map[string]struct{}{}

func (cfg Config) Validate(c path.ContextPath) (r report.Report) {
	systemdPath := "/etc/systemd/system/"
	unitPaths := map[string]struct{}{}
	for _, unit := range cfg.Systemd.Units {
		if !util.NilOrEmpty(unit.Contents) {
			pathString := systemdPath + unit.Name
			unitPaths[pathString] = struct{}{}
		}
		for _, dropin := range unit.Dropins {
			if !util.NilOrEmpty(dropin.Contents) {
				pathString := systemdPath + unit.Name + ".d/" + dropin.Name
				unitPaths[pathString] = struct{}{}
			}
		}
	}
	for i, f := range cfg.Storage.Files {
		if _, exists := unitPaths[f.Path]; exists {
			r.AddOnError(c.Append("storage", "files", i, "path"), errors.ErrPathConflictsSystemd)
		}
	}
	for i, d := range cfg.Storage.Directories {
		if _, exists := unitPaths[d.Path]; exists {
			r.AddOnError(c.Append("storage", "directories", i, "path"), errors.ErrPathConflictsSystemd)
		}
	}
	for i, l := range cfg.Storage.Links {
		if _, exists := unitPaths[l.Path]; exists {
			r.AddOnError(c.Append("storage", "links", i, "path"), errors.ErrPathConflictsSystemd)
		}
	}

	r.Merge(cfg.validateParents(c))

	return r
}

func (cfg Config) validateParents(c path.ContextPath) report.Report {
	var entries []struct {
		Path  string
		Field string
	}
	r := report.Report{}

	for i, f := range cfg.Storage.Files {
		fmt.Println("File variable value:", f) // Added print statement
		r = handlePathConflict(f.Path, "files", i, c, r, errors.ErrPathAlreadyExists)
		addPathAndEntry(f.Path, "files", &entries)
	}

	for i, d := range cfg.Storage.Directories {
		fmt.Println("Directory variable value:", d) // Added print statement
		r = handlePathConflict(d.Path, "directories", i, c, r, errors.ErrPathAlreadyExists)
		addPathAndEntry(d.Path, "directories", &entries)
	}

	for i, l := range cfg.Storage.Links {
		fmt.Println("Link variable value:", l) // Added print statement
		r = handlePathConflict(l.Path, "links", i, c, r, errors.ErrPathAlreadyExists)
		addPathAndEntry(l.Path, "links", &entries)
	}

	sort.Slice(entries, func(i, j int) bool {
		return depth(entries[i].Path) < depth(entries[j].Path)
	})

	for i, entry := range entries {
		fmt.Println("Entry variable value:", entry) // Added print statement
		if i > 0 && isWithin(entry.Path, entries[i-1].Path) {
			if entries[i-1].Field != "directories" {
				errorMsg := fmt.Errorf("invalid entry at path %s: %v", entry.Path, errors.ErrMissLabeledDir)
				r.AddOnError(c.Append("storage", entry.Field, i, "path"), errorMsg)
				fmt.Println("Error message:", errorMsg) // Added print statement
				return r
			}
		}
	}

	return r
}

func handlePathConflict(path, fieldName string, index int, c path.ContextPath, r report.Report, err error) report.Report {
	fmt.Println("Path variable value:", path) // Added print statement
	if _, exists := paths[path]; exists {
		r.AddOnError(c.Append("storage", fieldName, index, "path"), err)
		fmt.Println("Error:", err) // Added print statement
	}
	return r
}

func addPathAndEntry(path, fieldName string, entries *[]struct{ Path, Field string }) {
	*entries = append(*entries, struct {
		Path  string
		Field string
	}{Path: path, Field: fieldName})
	fmt.Println("Added entry:", path) // Added print statement
}

func depth(path string) uint {
	var count uint
	cleanedPath := filepath.FromSlash(filepath.Clean(path))
	sep := string(filepath.Separator)

	volume := filepath.VolumeName(cleanedPath)
	if volume != "" {
		cleanedPath = cleanedPath[len(volume):]
	}

	for cleanedPath != sep && cleanedPath != "." {
		cleanedPath = filepath.Dir(cleanedPath)
		count++
	}
	return count
}

func isWithin(newPath, prevPath string) bool {
	fmt.Println("New path variable value:", newPath)       // Added print statement
	fmt.Println("Previous path variable value:", prevPath) // Added print statement
	return strings.HasPrefix(newPath, prevPath) && newPath != prevPath
}
