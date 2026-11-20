package netx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// SealFile is the manifest of a sealed data snapshot, stored in the cache
// directory itself.
const SealFile = "ssca-seal.json"

// ErrSeal reports that a file of a sealed snapshot differs from its manifest
// (changed, or added after sealing). It is a self-check failure (exit code 4,
// NFR-07): the external data of the run cannot be trusted.
var ErrSeal = errors.New("sealed data snapshot modified")

// Seal is the manifest of a sealed data snapshot: the SHA-256 hash of every
// file. A snapshot is sealed once it is frozen (ssca cache seal); offline
// runs then check every file they read against the manifest. Online runs
// refresh the cache and do not use the seal.
type Seal struct {
	Created time.Time         `json:"created"`
	Files   map[string]string `json:"files"` // path relative to the cache directory -> hex SHA-256
	ID      string            `json:"id"`
}

func sealID(files map[string]string) string {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		io.WriteString(h, k+" "+files[k]+"\n")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:32]
}

func fileHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// SealCache writes the manifest of every file under dir and returns it.
func SealCache(dir string, now time.Time) (*Seal, error) {
	s := &Seal{Created: now.UTC().Truncate(time.Second), Files: map[string]string{}}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == SealFile {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s.Files[filepath.ToSlash(rel)] = fileHash(b)
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.ID = sealID(s.Files)
	out, _ := json.MarshalIndent(s, "", " ")
	return s, os.WriteFile(filepath.Join(dir, SealFile), out, 0o644)
}

// LoadSeal reads the manifest of dir; it returns nil, nil when the snapshot
// is not sealed. A manifest whose recorded ID does not match its contents is
// an error.
func LoadSeal(dir string) (*Seal, error) {
	b, err := os.ReadFile(filepath.Join(dir, SealFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Seal
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%w: %s unreadable: %v", ErrSeal, SealFile, err)
	}
	if s.ID != sealID(s.Files) {
		return nil, fmt.Errorf("%w: %s does not match its own ID", ErrSeal, SealFile)
	}
	return &s, nil
}

// Check compares a file of the snapshot (path relative to the cache
// directory) with the manifest.
func (s *Seal) Check(rel string, b []byte) error {
	want, ok := s.Files[filepath.ToSlash(rel)]
	if !ok {
		return fmt.Errorf("%w: %s is not in the manifest", ErrSeal, rel)
	}
	if fileHash(b) != want {
		return fmt.Errorf("%w: %s changed after sealing", ErrSeal, rel)
	}
	return nil
}

// CheckFile reads one file of the snapshot and checks it; a file that does
// not exist is not an error (the run will miss the data and say so).
func (s *Seal) CheckFile(dir, rel string) error {
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.Check(rel, b)
}
