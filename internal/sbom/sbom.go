// Package sbom is module M1: CycloneDX and SPDX generation, SBOM reading and
// validation against the CISA minimum elements, and SBOM diff.
package sbom

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Doc is the internal, format-neutral SBOM representation.
type Doc struct {
	Format     string
	Tool       string
	Author     string
	Timestamp  string
	Context    string // "pre-build" (lockfile) or "post-build"
	Components []Comp
	Edges      [][2]string // parent key -> child key (purl without version)
	Root       string
	// RootName and RootVersion name the root component as its ecosystem
	// does (npm "@scope/name", Maven "group:artifact"); FromGraph sets them.
	RootName, RootVersion string
	// Incomplete holds the reasons why the inventory may lack components
	// (model.Graph.Incomplete). CycloneDX records them as an "incomplete"
	// composition of the root and as properties, SPDX in the creation
	// comment, so that a consumer of the SBOM does not take it for complete.
	Incomplete []string
}

// Comp is one SBOM component.
type Comp struct {
	PURL    string
	Name    string // full native name (npm "@scope/name", Maven "group:artifact")
	Group   string // npm scope or Maven groupId; "" when there is none
	Short   string // Name without Group
	Version string
	// Supplier is a producer declared in the package metadata, never a
	// value derived from the package name or its repository.
	Supplier    string
	SupplierOrg bool
	Download    string // download URL or VCS location, "" if not known
	// Hashes lists the known hashes by algorithm: a Python release has one
	// file per platform, and every one of them is a valid form of the component.
	Hashes     map[string][]string
	Licenses   []string
	Ref        string
	Provenance string // builder or source repository, if known
	// Scope is the dependency scope; development and test dependencies are
	// marked in both formats (CycloneDX scope "excluded", SPDX
	// DEV_DEPENDENCY_OF / TEST_DEPENDENCY_OF), packages of the project's own
	// extras as CycloneDX scope "optional" and SPDX OPTIONAL_DEPENDENCY_OF.
	Scope model.Scope
	Eco   string
}

// addHash records a hash once; the values of an algorithm stay sorted.
func (c *Comp) addHash(alg, v string) {
	if !slices.Contains(c.Hashes[alg], v) {
		c.Hashes[alg] = append(c.Hashes[alg], v)
		slices.Sort(c.Hashes[alg])
	}
}

// FromGraph converts the component graph to a Doc.
func FromGraph(g *model.Graph, tool string, now time.Time) *Doc {
	d := &Doc{Format: "internal", Tool: tool, Author: "ssca", Timestamp: now.UTC().Format(time.RFC3339), Context: "pre-build", Root: g.Root}
	if r := g.Nodes[g.Root]; r != nil {
		d.RootName, d.RootVersion = r.FullName(), r.Version
	}
	seen := map[string]bool{}
	for _, r := range g.Incomplete {
		if !seen[r] {
			seen[r] = true
			d.Incomplete = append(d.Incomplete, r)
		}
	}
	for _, c := range g.Components() {
		cp := Comp{PURL: c.PURL, Name: c.FullName(), Group: c.Namespace, Short: c.Name, Version: c.Version, Licenses: c.Licenses, Ref: c.PURL, Hashes: map[string][]string{},
			Scope: c.Scope, Eco: c.Ecosystem, Download: downloadLocation(c)}
		for _, h := range c.Integrity {
			// an SRI value may list several hashes ("sha1-… sha512-…")
			for _, f := range strings.Fields(h) {
				if alg, hx := decodeHash(f); alg != "" {
					cp.addHash(alg, hx)
				}
			}
		}
		if c.Meta != nil {
			cp.Supplier, cp.SupplierOrg = c.Meta.Supplier, c.Meta.SupplierOrg
			// hashes published by the registry, when the lockfile records none
			if len(cp.Hashes) == 0 {
				if c.Meta.RepoSHA1 != "" {
					cp.addHash("SHA-1", c.Meta.RepoSHA1)
				}
				for _, h := range c.Meta.RepoSHA256 {
					cp.addHash("SHA-256", h)
				}
			}
		}
		d.Components = append(d.Components, cp)
	}
	for from, es := range g.Out {
		for _, e := range es {
			d.Edges = append(d.Edges, [2]string{from, e.To})
		}
	}
	sort.Slice(d.Edges, func(i, j int) bool { return d.Edges[i][0]+d.Edges[i][1] < d.Edges[j][0]+d.Edges[j][1] })
	return d
}

// downloadLocation returns the location of an npm package recorded in the
// lockfile, if it is a URL that an SBOM may carry: not a local path, and
// without credentials. (PyPI and Maven components record an index or nothing
// there, not the location of the package.)
func downloadLocation(c *model.Component) string {
	if c.Ecosystem != model.NPM {
		return ""
	}
	u, err := url.Parse(c.Resolved)
	if err != nil || u.Host == "" || u.User != nil {
		return ""
	}
	switch u.Scheme {
	case "http", "https", "git+http", "git+https":
		return c.Resolved
	}
	return ""
}

// decodeHash converts "sha512-<b64>" or "sha256:<hex>" to (alg, hex).
func decodeHash(h string) (string, string) {
	if alg, b64, ok := strings.Cut(h, "-"); ok && (alg == "sha512" || alg == "sha384" || alg == "sha256" || alg == "sha1") {
		if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
			return strings.ToUpper(strings.Replace(alg, "sha", "SHA-", 1)), hex.EncodeToString(raw)
		}
	}
	if alg, hx, ok := strings.Cut(h, ":"); ok {
		return strings.ToUpper(strings.Replace(alg, "sha", "SHA-", 1)), strings.ToLower(hx)
	}
	return "", ""
}

// ---------------------------------------------------------------- CycloneDX

// CycloneDX renders the document as CycloneDX 1.6 JSON.
func (d *Doc) CycloneDX(rootName, rootVersion string) ([]byte, error) {
	type hash struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	}
	type lic struct {
		License *struct {
			ID   string `json:"id,omitempty"`
			Name string `json:"name,omitempty"`
		} `json:"license,omitempty"`
		Expression string `json:"expression,omitempty"`
	}
	type prop struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type extRef struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	type comp struct {
		Type     string `json:"type"`
		BOMRef   string `json:"bom-ref"`
		Group    string `json:"group,omitempty"`
		Name     string `json:"name"`
		Version  string `json:"version"`
		PURL     string `json:"purl"`
		Supplier *struct {
			Name string `json:"name"`
		} `json:"supplier,omitempty"`
		Hashes     []hash   `json:"hashes,omitempty"`
		Licenses   []lic    `json:"licenses,omitempty"`
		Scope      string   `json:"scope,omitempty"`
		ExtRefs    []extRef `json:"externalReferences,omitempty"`
		Properties []prop   `json:"properties,omitempty"`
	}
	type dep struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	}
	out := map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"serialNumber": "urn:uuid:" + uuidFrom(d.Root+d.Timestamp),
	}
	meta := map[string]any{
		"timestamp":  d.Timestamp,
		"lifecycles": []map[string]string{{"phase": map[string]string{"pre-build": "pre-build", "post-build": "post-build"}[d.Context]}},
		"tools":      map[string]any{"components": []map[string]string{{"type": "application", "name": "ssca", "version": d.Tool}}},
		"authors":    []map[string]string{{"name": d.Author}},
		"component":  map[string]string{"type": "application", "bom-ref": d.Root, "name": rootName, "version": rootVersion, "purl": d.Root},
	}
	if len(d.Incomplete) > 0 {
		// CycloneDX 1.6 compositions: the components and dependencies of the
		// root are known to be incomplete; the reasons are kept as properties
		var props []prop
		for _, r := range d.Incomplete {
			props = append(props, prop{"ssca:incomplete", r})
		}
		meta["properties"] = props
		out["compositions"] = []map[string]any{{"aggregate": "incomplete", "assemblies": []string{d.Root}, "dependencies": []string{d.Root}}}
	}
	out["metadata"] = meta
	var comps []comp
	for _, c := range d.Components {
		x := comp{Type: "library", BOMRef: c.Ref, Name: c.Name, Version: c.Version, PURL: c.PURL}
		if c.Group != "" {
			x.Group, x.Name = c.Group, c.Short
		}
		if c.Download != "" {
			t := "distribution"
			if strings.HasPrefix(c.Download, "git+") {
				t = "vcs"
			}
			x.ExtRefs = []extRef{{t, c.Download}}
		}
		if c.Scope == model.ScopeExtra {
			// needed only by an extra of the project, which is installed on
			// request: CycloneDX scope "optional" (not installed by default)
			x.Scope = "optional"
			x.Properties = append(x.Properties, prop{"ssca:scope", string(c.Scope)})
		} else if c.Scope != "" && !c.Scope.Production() {
			// not part of the shipped application (CycloneDX 1.6 component scope)
			x.Scope = "excluded"
			if c.Eco == model.NPM {
				x.Properties = append(x.Properties, prop{"cdx:npm:package:development", "true"})
			}
			x.Properties = append(x.Properties, prop{"ssca:scope", string(c.Scope)})
		}
		if c.Supplier != "" {
			x.Supplier = &struct {
				Name string `json:"name"`
			}{c.Supplier}
		}
		algs := make([]string, 0, len(c.Hashes))
		for a := range c.Hashes {
			algs = append(algs, a)
		}
		sort.Strings(algs)
		for _, a := range algs {
			for _, v := range c.Hashes[a] {
				x.Hashes = append(x.Hashes, hash{a, v})
			}
		}
		for _, l := range c.Licenses {
			if strings.ContainsAny(l, " ()") {
				x.Licenses = append(x.Licenses, lic{Expression: l})
			} else {
				x.Licenses = append(x.Licenses, lic{License: &struct {
					ID   string `json:"id,omitempty"`
					Name string `json:"name,omitempty"`
				}{ID: l}})
			}
		}
		comps = append(comps, x)
	}
	out["components"] = comps
	deps := map[string][]string{}
	for _, e := range d.Edges {
		deps[e[0]] = append(deps[e[0]], e[1])
	}
	var dl []dep
	keys := make([]string, 0, len(deps))
	for k := range deps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		dl = append(dl, dep{k, deps[k]})
	}
	out["dependencies"] = dl
	return json.MarshalIndent(out, "", "  ")
}

// ---------------------------------------------------------------- SPDX

// SPDX renders the document as SPDX 2.3 JSON.
func (d *Doc) SPDX(rootName string) ([]byte, error) {
	id := func(purl string) string {
		h := sha256.Sum256([]byte(purl))
		return "SPDXRef-Package-" + hex.EncodeToString(h[:6])
	}
	type ext struct {
		Category string `json:"referenceCategory"`
		Type     string `json:"referenceType"`
		Locator  string `json:"referenceLocator"`
	}
	type cks struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"checksumValue"`
	}
	type pkg struct {
		SPDXID           string `json:"SPDXID"`
		Name             string `json:"name"`
		Version          string `json:"versionInfo"`
		Supplier         string `json:"supplier,omitempty"`
		Download         string `json:"downloadLocation"`
		FilesAnalyzed    bool   `json:"filesAnalyzed"`
		LicenseDeclared  string `json:"licenseDeclared"`
		LicenseConcluded string `json:"licenseConcluded"`
		Copyright        string `json:"copyrightText"`
		Checksums        []cks  `json:"checksums,omitempty"`
		Refs             []ext  `json:"externalRefs"`
		Comment          string `json:"comment,omitempty"`
	}
	type rel struct {
		A    string `json:"spdxElementId"`
		Type string `json:"relationshipType"`
		B    string `json:"relatedSpdxElement"`
	}
	pkgs := []pkg{{SPDXID: id(d.Root), Name: rootName, Version: "", Download: "NOASSERTION", LicenseDeclared: "NOASSERTION", LicenseConcluded: "NOASSERTION", Copyright: "NOASSERTION", Refs: []ext{{"PACKAGE-MANAGER", "purl", d.Root}}}}
	for _, c := range d.Components {
		p := pkg{SPDXID: id(c.PURL), Name: c.Name, Version: c.Version, Download: "NOASSERTION",
			LicenseDeclared: "NOASSERTION", LicenseConcluded: "NOASSERTION", Copyright: "NOASSERTION",
			Refs: []ext{{"PACKAGE-MANAGER", "purl", c.PURL}}}
		if c.Download != "" {
			p.Download = c.Download
		}
		if len(c.Licenses) == 1 && !strings.ContainsAny(c.Licenses[0], " ") {
			p.LicenseDeclared = c.Licenses[0]
		}
		if c.Supplier != "" {
			p.Supplier = "Person: " + c.Supplier
			if c.SupplierOrg {
				p.Supplier = "Organization: " + c.Supplier
			}
		}
		if c.Scope == model.ScopeExtra {
			p.Comment = "scope: extra (needed only by an optional feature of the project, installed on request)"
		} else if c.Scope != "" && !c.Scope.Production() {
			p.Comment = "scope: " + string(c.Scope) + " (not part of the shipped application)"
		}
		for a, vs := range c.Hashes {
			for _, v := range vs {
				p.Checksums = append(p.Checksums, cks{strings.ReplaceAll(a, "-", ""), v})
			}
		}
		sort.Slice(p.Checksums, func(i, j int) bool {
			a, b := p.Checksums[i], p.Checksums[j]
			return a.Algorithm < b.Algorithm || a.Algorithm == b.Algorithm && a.Value < b.Value
		})
		pkgs = append(pkgs, p)
	}
	rels := []rel{{"SPDXRef-DOCUMENT", "DESCRIBES", id(d.Root)}}
	// every edge to a development or test package is DEV_DEPENDENCY_OF or
	// TEST_DEPENDENCY_OF instead of DEPENDS_ON, also below the root, so that
	// the scope of a transitive package can be read from the relationships
	// (its parent stays the real one: the graph is unchanged on reading)
	devRel := map[string]string{}
	for _, c := range d.Components {
		switch c.Scope {
		case model.ScopeDev:
			devRel[c.PURL] = "DEV_DEPENDENCY_OF"
		case model.ScopeTest:
			devRel[c.PURL] = "TEST_DEPENDENCY_OF"
		case model.ScopeExtra:
			devRel[c.PURL] = "OPTIONAL_DEPENDENCY_OF"
		}
	}
	for _, e := range d.Edges {
		if t := devRel[e[1]]; t != "" {
			rels = append(rels, rel{id(e[1]), t, id(e[0])})
		} else {
			rels = append(rels, rel{id(e[0]), "DEPENDS_ON", id(e[1])})
		}
	}
	ci := map[string]any{"created": d.Timestamp, "creators": []string{"Tool: ssca-" + d.Tool, "Organization: " + d.Author}}
	// SPDX 2.3 has no field for the generation context (CycloneDX
	// lifecycles) or for completeness; the creation comment is the place for
	// information about how the document was made
	var comment []string
	if d.Context != "" {
		comment = append(comment, spdxContext+d.Context+".")
	}
	if len(d.Incomplete) > 0 {
		comment = append(comment, spdxIncomplete+strings.Join(d.Incomplete, "; "))
	}
	if len(comment) > 0 {
		ci["comment"] = strings.Join(comment, " ")
	}
	out := map[string]any{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
		"name": rootName, "documentNamespace": "https://ssca.local/spdx/" + uuidFrom(d.Root+d.Timestamp),
		"creationInfo": ci,
		"packages":     pkgs, "relationships": rels,
	}
	return json.MarshalIndent(out, "", "  ")
}

// spdxIncomplete starts the part of the creation comment of an SPDX document
// that was made from an incomplete analysis; Read recognises it. It is the
// last part of the comment, so the reasons run to its end.
const spdxIncomplete = "Incomplete analysis, components may be missing: "

// spdxContext starts the generation context in the creation comment of an
// SPDX document ("Generation context: pre-build."), the lifecycle phase of
// CycloneDX: pre-build for an SBOM made from lockfiles and manifests.
const spdxContext = "Generation context: "

// spdxContextRe reads the generation context of a creation comment.
var spdxContextRe = regexp.MustCompile(`Generation context: ([a-z-]+)`)

func uuidFrom(s string) string {
	h := sha256.Sum256([]byte(s))
	x := hex.EncodeToString(h[:16])
	return x[0:8] + "-" + x[8:12] + "-4" + x[13:16] + "-a" + x[17:20] + "-" + x[20:32]
}

// ---------------------------------------------------------------- reading

// Read parses a CycloneDX or SPDX JSON SBOM (also Syft and Trivy output).
func Read(path string) (*Doc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("%s: not JSON: %w", path, err)
	}
	switch {
	case probe["bomFormat"] != nil:
		return readCDX(b)
	case probe["spdxVersion"] != nil:
		return readSPDX(b)
	}
	return nil, fmt.Errorf("%s: unknown SBOM format", path)
}

func readCDX(b []byte) (*Doc, error) {
	var x struct {
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Timestamp  string `json:"timestamp"`
			Authors    []any  `json:"authors"`
			Tools      any    `json:"tools"`
			Lifecycles []struct {
				Phase string `json:"phase"`
			} `json:"lifecycles"`
			Component struct {
				BOMRef string `json:"bom-ref"`
				PURL   string `json:"purl"`
			} `json:"component"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
		Components   []cdxComp `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
		Compositions []struct {
			Aggregate  string   `json:"aggregate"`
			Assemblies []string `json:"assemblies"`
		} `json:"compositions"`
	}
	if err := json.Unmarshal(b, &x); err != nil {
		return nil, err
	}
	d := &Doc{Format: "CycloneDX " + x.SpecVersion, Timestamp: x.Metadata.Timestamp, Root: x.Metadata.Component.BOMRef}
	for _, p := range x.Metadata.Properties {
		if p.Name == "ssca:incomplete" {
			d.Incomplete = append(d.Incomplete, p.Value)
		}
	}
	for _, c := range x.Compositions {
		if strings.HasPrefix(c.Aggregate, "incomplete") && slices.Contains(c.Assemblies, d.Root) && len(d.Incomplete) == 0 {
			d.Incomplete = []string{"the SBOM declares its composition " + c.Aggregate}
		}
	}
	if len(x.Metadata.Authors) > 0 {
		d.Author = "present"
	}
	if x.Metadata.Tools != nil {
		d.Tool = "present"
	}
	if len(x.Metadata.Lifecycles) > 0 {
		d.Context = x.Metadata.Lifecycles[0].Phase
	}
	refToPurl := map[string]string{}
	var flat []cdxComp
	var walk func([]cdxComp)
	walk = func(cs []cdxComp) {
		for _, c := range cs {
			flat = append(flat, c)
			walk(c.Components)
		}
	}
	walk(x.Components)
	for _, c := range flat {
		if c.PURL == "" {
			continue
		}
		cp := Comp{PURL: c.PURL, Name: c.Name, Group: c.Group, Short: c.Name, Version: c.Version, Ref: c.BOMRef, Hashes: map[string][]string{}}
		if c.Group != "" {
			sep := "/"
			if strings.HasPrefix(c.PURL, "pkg:maven/") {
				sep = ":"
			}
			cp.Name = c.Group + sep + c.Name
		}
		switch c.Scope {
		case "excluded":
			cp.Scope = model.ScopeDev
		case "optional":
			cp.Scope = model.ScopeExtra
		}
		if c.Supplier != nil {
			cp.Supplier = c.Supplier.Name
		}
		if cp.Supplier == "" && c.Publisher != "" {
			cp.Supplier = c.Publisher
		}
		for _, h := range c.Hashes {
			cp.addHash(h.Alg, strings.ToLower(h.Content))
		}
		for _, l := range c.Licenses {
			switch {
			case l.Expression != "":
				cp.Licenses = append(cp.Licenses, l.Expression)
			case l.License.ID != "":
				cp.Licenses = append(cp.Licenses, l.License.ID)
			case l.License.Name != "":
				cp.Licenses = append(cp.Licenses, l.License.Name)
			}
		}
		refToPurl[c.BOMRef] = c.PURL
		d.Components = append(d.Components, cp)
	}
	refToPurl[x.Metadata.Component.BOMRef] = x.Metadata.Component.PURL
	for _, dep := range x.Dependencies {
		for _, t := range dep.DependsOn {
			a, b := refToPurl[dep.Ref], refToPurl[t]
			if a == "" {
				a = dep.Ref
			}
			if b != "" {
				d.Edges = append(d.Edges, [2]string{a, b})
			}
		}
	}
	return d, nil
}

type cdxComp struct {
	BOMRef    string `json:"bom-ref"`
	Name      string `json:"name"`
	Group     string `json:"group"`
	Version   string `json:"version"`
	PURL      string `json:"purl"`
	Publisher string `json:"publisher"`
	Supplier  *struct {
		Name string `json:"name"`
	} `json:"supplier"`
	Hashes []struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	} `json:"hashes"`
	Licenses []struct {
		License struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
		Expression string `json:"expression"`
	} `json:"licenses"`
	Scope      string    `json:"scope"`
	Components []cdxComp `json:"components"`
}

func readSPDX(b []byte) (*Doc, error) {
	var x struct {
		SPDXVersion  string `json:"spdxVersion"`
		CreationInfo struct {
			Created  string   `json:"created"`
			Creators []string `json:"creators"`
			Comment  string   `json:"comment"`
		} `json:"creationInfo"`
		Packages []struct {
			SPDXID    string `json:"SPDXID"`
			Name      string `json:"name"`
			Version   string `json:"versionInfo"`
			Supplier  string `json:"supplier"`
			License   string `json:"licenseDeclared"`
			Checksums []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"checksumValue"`
			} `json:"checksums"`
			Refs []struct {
				Type    string `json:"referenceType"`
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
		Relationships []struct {
			A    string `json:"spdxElementId"`
			Type string `json:"relationshipType"`
			B    string `json:"relatedSpdxElement"`
		} `json:"relationships"`
		Describes []string `json:"documentDescribes"`
	}
	if err := json.Unmarshal(b, &x); err != nil {
		return nil, err
	}
	d := &Doc{Format: x.SPDXVersion, Timestamp: x.CreationInfo.Created}
	if i := strings.Index(x.CreationInfo.Comment, spdxIncomplete); i >= 0 {
		d.Incomplete = strings.Split(x.CreationInfo.Comment[i+len(spdxIncomplete):], "; ")
	}
	if m := spdxContextRe.FindStringSubmatch(x.CreationInfo.Comment); m != nil {
		d.Context = m[1]
	}
	for _, c := range x.CreationInfo.Creators {
		if strings.HasPrefix(c, "Tool:") {
			d.Tool = c
		}
		if strings.HasPrefix(c, "Organization:") || strings.HasPrefix(c, "Person:") {
			d.Author = c
		}
	}
	idToPurl := map[string]string{}
	for _, p := range x.Packages {
		purl := ""
		for _, r := range p.Refs {
			if r.Type == "purl" {
				purl = r.Locator
			}
		}
		if purl == "" {
			continue
		}
		idToPurl[p.SPDXID] = purl
		cp := Comp{PURL: purl, Name: p.Name, Version: p.Version, Supplier: strings.TrimPrefix(strings.TrimPrefix(p.Supplier, "Organization: "), "Person: "), Ref: p.SPDXID, Hashes: map[string][]string{}}
		if cp.Supplier == "NOASSERTION" {
			cp.Supplier = ""
		}
		if p.License != "" && p.License != "NOASSERTION" {
			cp.Licenses = []string{p.License}
		}
		for _, c := range p.Checksums {
			cp.addHash(c.Algorithm, strings.ToLower(c.Value))
		}
		d.Components = append(d.Components, cp)
	}
	// the package that the document describes is the subject of the SBOM
	// (metadata.component in CycloneDX), not one of its components; a
	// document that describes several packages keeps them all
	described := x.Describes
	scopes := map[string]model.Scope{}
	for _, r := range x.Relationships {
		if r.Type == "DESCRIBES" && r.A == "SPDXRef-DOCUMENT" {
			described = append(described, r.B)
		}
		if idToPurl[r.A] == "" || idToPurl[r.B] == "" {
			continue
		}
		switch r.Type {
		case "DEPENDS_ON":
			d.Edges = append(d.Edges, [2]string{idToPurl[r.A], idToPurl[r.B]})
		case "DEV_DEPENDENCY_OF", "TEST_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF":
			// "A DEV_DEPENDENCY_OF B": B depends on A during development
			d.Edges = append(d.Edges, [2]string{idToPurl[r.B], idToPurl[r.A]})
			switch r.Type {
			case "TEST_DEPENDENCY_OF":
				scopes[idToPurl[r.A]] = model.ScopeTest
			case "OPTIONAL_DEPENDENCY_OF":
				scopes[idToPurl[r.A]] = model.ScopeExtra
			default:
				scopes[idToPurl[r.A]] = model.ScopeDev
			}
		}
	}
	for i := range d.Components {
		d.Components[i].Scope = scopes[d.Components[i].PURL]
	}
	if len(described) == 1 {
		d.Root = described[0]
		if p := idToPurl[d.Root]; p != "" {
			d.Root = p
		}
		kept := d.Components[:0]
		for _, c := range d.Components {
			if c.Ref != described[0] {
				kept = append(kept, c)
			}
		}
		d.Components = kept
	}
	return d, nil
}

// ---------------------------------------------------------------- completeness

// Completeness scores an SBOM against the CISA minimum elements.
type Completeness struct {
	Score    float64            `json:"score"`
	Elements map[string]float64 `json:"elements"`
}

// Assess computes the share of components (or the document) that carry each
// minimum element; the score is the mean over all elements. An SBOM that
// states that it is incomplete does not meet the dependency relationships
// element: the number of missing components is unknown, so the shares of the
// per-component elements cannot be corrected for them.
func (d *Doc) Assess() Completeness {
	n := float64(len(d.Components))
	el := map[string]float64{}
	doc := func(ok bool) float64 {
		if ok {
			return 1
		}
		return 0
	}
	el["sbom_author"] = doc(d.Author != "")
	el["tool"] = doc(d.Tool != "")
	el["timestamp"] = doc(d.Timestamp != "")
	el["generation_context"] = doc(d.Context != "")
	if n > 0 {
		var name, ver, id, sup, hash, lic float64
		for _, c := range d.Components {
			name += doc(c.Name != "")
			ver += doc(c.Version != "")
			id += doc(c.PURL != "")
			sup += doc(c.Supplier != "")
			hash += doc(len(c.Hashes) > 0)
			lic += doc(len(c.Licenses) > 0)
		}
		el["component_name"], el["version"], el["identifier"] = name/n, ver/n, id/n
		el["producer"], el["hash"], el["license"] = sup/n, hash/n, lic/n
	}
	withEdges := map[string]bool{}
	for _, e := range d.Edges {
		withEdges[e[0]] = true
	}
	el["dependency_relationships"] = doc(len(d.Edges) > 0 && len(d.Incomplete) == 0)
	var s float64
	for _, v := range el {
		s += v
	}
	return Completeness{Score: s / float64(len(el)), Elements: el}
}
