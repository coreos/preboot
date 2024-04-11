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
	paths := map[string]struct{}{}
	r := report.Report{}

	for i, f := range cfg.Storage.Files {
		if _, exists := paths[f.Path]; exists {
			r.AddOnError(c.Append("storage", "files", i, "path"), errors.ErrPathConflictsParentDir) //TODO:  should add different error?
			return r
		}
		paths[f.Path] = struct{}{}
		entries = append(entries, struct {
			Path  string
			Field string
		}{Path: f.Path, Field: "files"})
	}

	for i, d := range cfg.Storage.Directories {
		if _, exists := paths[d.Path]; exists {
			r.AddOnError(c.Append("storage", "directories", i, "path"), errors.ErrPathConflictsParentDir) //TODO: should add different error?
			return r
		}
		paths[d.Path] = struct{}{}
		entries = append(entries, struct {
			Path  string
			Field string
		}{Path: d.Path, Field: "directories"})
	}

	for i, l := range cfg.Storage.Links {
		if _, exists := paths[l.Path]; exists {
			r.AddOnError(c.Append("storage", "links", i, "path"), errors.ErrPathConflictsParentDir) //TODO:  error to already exist path
			return r
		}
		paths[l.Path] = struct{}{}
		entries = append(entries, struct {
			Path  string
			Field string
		}{Path: l.Path, Field: "links"})
	}

	sort.Slice(entries, func(i, j int) bool {
		return depth(entries[i].Path) < depth(entries[j].Path)
	})

	for i, entry := range entries {
		if i > 0 && isWithin(entry.Path, entries[i-1].Path) {
			if entries[i-1].Field != "directories" {
				r.AddOnError(c.Append("storage", entry.Field, i, "path"), errors.ErrPathConflictsParentDir) //TODO: conflict parent directories error
				return r
			}
		}
	}

	return r
}

// check the depth
func depth(path string) uint {
	var count uint
	for p := filepath.Clean(path); p != "/" && p != "."; count++ {
		p = filepath.Dir(p)
	}
	return count
}

// isWithin checks if newPath is within prevPath.
func isWithin(newPath, prevPath string) bool {
	return strings.HasPrefix(newPath, prevPath) && newPath != prevPath
}
