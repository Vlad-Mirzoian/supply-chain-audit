package netx

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CacheHost summarises the cached responses of one data source.
type CacheHost struct {
	Host      string    `json:"host"`
	Responses int       `json:"responses"`
	Fresh     int       `json:"fresh"`     // younger than DefaultTTL: an online run does not fetch them again
	NotFound  int       `json:"not_found"` // cached "this does not exist" answers
	Bytes     int64     `json:"bytes"`
	Newest    time.Time `json:"newest"`
}

// CacheStats is the state of a cache directory.
type CacheStats struct {
	Dir        string      `json:"dir"`
	Responses  int         `json:"responses"`
	Fresh      int         `json:"fresh"`
	Bytes      int64       `json:"bytes"`
	Oldest     time.Time   `json:"oldest,omitzero"`
	Newest     time.Time   `json:"newest,omitzero"`
	Unreadable int         `json:"unreadable"` // files that are not valid cache entries
	Hosts      []CacheHost `json:"hosts"`
}

// InspectCache reads the state of a cache directory without changing it.
func InspectCache(dir string, now time.Time) (*CacheStats, error) {
	top, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	st := &CacheStats{Dir: dir, Hosts: []CacheHost{}}
	hosts := map[string]*CacheHost{}
	for _, d := range top {
		if !d.IsDir() || len(d.Name()) != 2 { // entries are stored as xx/<sha256>.json
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, d.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			p := filepath.Join(dir, d.Name(), f.Name())
			e, err := readEntryHead(p)
			if err != nil {
				st.Unreadable++
				continue
			}
			u, err := url.Parse(e.URL)
			if err != nil || u.Host == "" {
				st.Unreadable++
				continue
			}
			var size int64
			if info, err := f.Info(); err == nil {
				size = info.Size()
			}
			h := hosts[u.Host]
			if h == nil {
				h = &CacheHost{Host: u.Host}
				hosts[u.Host] = h
			}
			h.Responses++
			h.Bytes += size
			st.Responses++
			st.Bytes += size
			if now.Sub(e.Fetched) < DefaultTTL {
				h.Fresh++
				st.Fresh++
			}
			if e.Status == http.StatusNotFound || e.Status == http.StatusGone {
				h.NotFound++
			}
			if e.Fetched.After(h.Newest) {
				h.Newest = e.Fetched
			}
			if st.Oldest.IsZero() || e.Fetched.Before(st.Oldest) {
				st.Oldest = e.Fetched
			}
			if e.Fetched.After(st.Newest) {
				st.Newest = e.Fetched
			}
		}
	}
	for _, h := range hosts {
		st.Hosts = append(st.Hosts, *h)
	}
	sort.Slice(st.Hosts, func(i, j int) bool {
		if st.Hosts[i].Responses != st.Hosts[j].Responses {
			return st.Hosts[i].Responses > st.Hosts[j].Responses
		}
		return st.Hosts[i].Host < st.Hosts[j].Host
	})
	return st, nil
}

// readEntryHead reads the fields before the body of a cache entry; the body
// is the bulk of the file (up to MaxBody) and is not needed here.
func readEntryHead(path string) (cacheEntry, error) {
	var e cacheEntry
	f, err := os.Open(path)
	if err != nil {
		return e, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return e, fmt.Errorf("%s: not a cache entry", path)
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return e, err
		}
		switch k {
		case "url":
			err = dec.Decode(&e.URL)
		case "status":
			err = dec.Decode(&e.Status)
		case "fetched":
			err = dec.Decode(&e.Fetched)
		}
		if err != nil {
			return e, err
		}
		if k != "url" && k != "status" && k != "fetched" {
			break
		}
	}
	if e.URL == "" || e.Fetched.IsZero() {
		return e, errors.New(path + ": not a cache entry")
	}
	return e, nil
}
