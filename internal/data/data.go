// Package data embeds the versioned data snapshot shipped with the suite:
// the popular-package corpora used by the typosquatting detector. Their
// hashes are checked at start-up (self-protection, NFR-07, exit code 4).
package data

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
)

//go:embed popular-npm.json
var npmCorpus []byte

//go:embed popular-pypi.json
var pypiCorpus []byte

//go:embed SHA256SUMS
var sums string

type corpusFile struct {
	Source  string         `json:"source"`
	Fetched string         `json:"fetched"`
	Rows    []risk.Popular `json:"rows"`
}

func raw(eco string) ([]byte, string) {
	switch eco {
	case "npm":
		return npmCorpus, "popular-npm.json"
	case "pypi":
		return pypiCorpus, "popular-pypi.json"
	}
	return nil, ""
}

// SelfCheck verifies the embedded snapshot against SHA256SUMS.
func SelfCheck() error {
	for _, eco := range []string{"npm", "pypi"} {
		b, name := raw(eco)
		h := sha256.Sum256(b)
		want := ""
		for _, l := range strings.Split(sums, "\n") {
			f := strings.Fields(l)
			if len(f) == 2 && f[1] == name {
				want = f[0]
			}
		}
		if want != hex.EncodeToString(h[:]) {
			return fmt.Errorf("data snapshot %s: hash mismatch", name)
		}
	}
	return nil
}

// Corpus returns the popular-package corpus for an ecosystem. top limits the
// number of names (0 = all). The SSCA_CORPUS_<ECO> variable can point to a
// replacement file (used in the experiments).
func Corpus(eco string, top int) ([]risk.Popular, string, error) {
	b, name := raw(eco)
	if p := os.Getenv("SSCA_CORPUS_" + strings.ToUpper(eco)); p != "" {
		var err error
		if b, err = os.ReadFile(p); err != nil {
			return nil, "", err
		}
		name = p
	}
	if b == nil {
		return nil, "", nil
	}
	var f corpusFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, "", fmt.Errorf("%s: %w", name, err)
	}
	rows := f.Rows
	if top > 0 && top < len(rows) {
		rows = rows[:top]
	}
	return rows, f.Source + " " + f.Fetched, nil
}
