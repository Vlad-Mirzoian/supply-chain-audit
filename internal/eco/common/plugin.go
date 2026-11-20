// Package common defines the ecosystem plugin interface (NFR-05): everything
// that differs between npm, PyPI and Maven is hidden behind it.
package common

import (
	"context"
	"os"
	"path/filepath"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// Options control graph construction.
type Options struct {
	Net        *netx.Client
	IncludeDev bool
	// MaxRounds bounds the PyPI re-selection loop of Algorithm 3.1 (R).
	MaxRounds int
	// ForceResolve ignores lockfiles and resolves from manifests.
	ForceResolve bool
}

// Plugin is implemented by every ecosystem.
type Plugin interface {
	Name() string
	// Detect returns the manifests and lockfiles of this ecosystem in dir.
	Detect(dir string) []string
	// Load builds the dependency graph of the project in dir (Algorithm 3.1).
	Load(ctx context.Context, dir string, opt Options) (*model.Graph, error)
}

// Exists reports whether dir/name is a regular file.
func Exists(dir, name string) bool {
	st, err := os.Stat(filepath.Join(dir, name))
	return err == nil && !st.IsDir()
}

// DirName returns the name of the project directory, used as the root name
// when the manifest does not declare one ("." becomes the working directory's
// name instead of ".").
func DirName(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return filepath.Base(dir)
}
