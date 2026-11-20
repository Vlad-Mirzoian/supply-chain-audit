package vuln

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// EPSSURL is the FIRST EPSS API endpoint.
var EPSSURL = "https://api.first.org/data/v1/epss"

// EPSS fetches exploit-prediction scores from FIRST.
type EPSS struct {
	Net *netx.Client
}

// Scores returns the EPSS probability of each CVE (batched, 80 per call).
func (e *EPSS) Scores(ctx context.Context, cves []string) (map[string]float64, error) {
	uniq := map[string]bool{}
	for _, c := range cves {
		uniq[c] = true
	}
	list := make([]string, 0, len(uniq))
	for c := range uniq {
		list = append(list, c)
	}
	sort.Strings(list)
	out := map[string]float64{}
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	for i := 0; i < len(list); i += 80 {
		part := list[i:min(i+80, len(list))]
		wg.Add(1)
		go func(part []string) {
			defer wg.Done()
			var resp struct {
				Data []struct {
					CVE  string `json:"cve"`
					EPSS string `json:"epss"`
				} `json:"data"`
			}
			err := e.Net.GetJSON(ctx, EPSSURL+"?limit=100&cve="+strings.Join(part, ","), &resp)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			for _, d := range resp.Data {
				if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
					out[d.CVE] = f
				}
			}
		}(part)
	}
	wg.Wait()
	return out, firstErr
}

// KEV loads the CISA Known Exploited Vulnerabilities catalogue.
type KEV struct {
	Net  *netx.Client
	once sync.Once
	set  map[string]bool
	err  error
}

// KEVURL is the JSON feed of the catalogue.
var KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// Set returns the CVE identifiers in the catalogue.
func (k *KEV) Set(ctx context.Context) (map[string]bool, error) {
	k.once.Do(func() {
		var cat struct {
			Vulnerabilities []struct {
				CVE string `json:"cveID"`
			} `json:"vulnerabilities"`
		}
		k.err = k.Net.GetJSON(ctx, KEVURL, &cat)
		k.set = map[string]bool{}
		for _, v := range cat.Vulnerabilities {
			k.set[v.CVE] = true
		}
	})
	return k.set, k.err
}

func containsStr(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
