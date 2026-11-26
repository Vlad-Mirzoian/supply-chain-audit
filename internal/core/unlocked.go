package core

import (
	"path/filepath"
	"slices"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Lockfiles are the files that pin the versions and hashes of an ecosystem.
// Maven has no lockfile.
var Lockfiles = map[string][]string{
	model.NPM:  {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"},
	model.PyPI: {"uv.lock", "poetry.lock", "Pipfile.lock"},
}

// Unlocked counts, per ecosystem, the package versions that come from
// manifests without a lockfile (or were resolved with --resolve), given the
// input files and the components of a graph: their hashes are not pinned by
// the project, and the versions that the manifests do not pin exactly are
// resolved at the time of the run, so they can differ from those that an
// installation gets. A requirements file that pins every package with
// --hash counts as locked.
func Unlocked(inputs []string, comps []*model.Component) map[string]int {
	locked := map[string]bool{}
	for _, in := range inputs {
		for eco, names := range Lockfiles {
			if slices.Contains(names, filepath.Base(in)) {
				locked[eco] = true
			}
		}
	}
	out := map[string]int{}
	for _, c := range comps {
		if _, ok := Lockfiles[c.Ecosystem]; ok && len(c.Integrity) == 0 && !locked[c.Ecosystem] {
			out[c.Ecosystem]++
		}
	}
	return out
}
