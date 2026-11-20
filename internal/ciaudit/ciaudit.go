// Package ciaudit is module M5: static checks of CI/CD configuration that
// address threats T-05 and T-07 (unpinned actions, unsafe triggers, token
// permissions, install scripts and script injection).
package ciaudit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

var (
	shaRef      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	installCmd  = regexp.MustCompile(`\b(npm (ci|install|i)\b|yarn( install)?\s*$|yarn install|pnpm (install|i)\b)`)
	pipeToShell = regexp.MustCompile(`(curl|wget)[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b`)
	// expressions and the attacker-controlled contexts that may appear
	// anywhere inside them ("${{ github.event.issue.title || 'x' }}",
	// "${{ github.event.commits[0].message }}")
	expression = regexp.MustCompile(`\$\{\{[^}]*\}\}`)
	untrusted  = regexp.MustCompile(`github\.head_ref\b|github\.event\.(` +
		`(issue|discussion|pull_request)\.(title|body)\b|` +
		`(comment|review|review_comment)\.body\b|` +
		`pull_request\.head\.(ref|label|repo\.default_branch)\b|` +
		`pages(\[[^\]]*\]|\.\*)?\.page_name\b|` +
		`(workflow_run\.)?head_commit\.(message|author\.(email|name))\b|` +
		`commits(\[[^\]]*\]|\.\*)?\.(message|author\.(email|name))\b|` +
		`workflow_run\.(head_branch|display_title)\b)`)
	// references to the code of a pull request or of the run that triggered
	// workflow_run, which a privileged workflow must not check out
	headCheckout = regexp.MustCompile(`github\.event\.pull_request\.head\.(sha|ref|repo\.full_name)|github\.head_ref|` +
		`github\.event\.workflow_run\.(head_sha|head_branch|head_repository\.full_name)|refs/pull/`)
	// shell commands that fetch the code of a pull request: "gh pr checkout",
	// and git commands with a pull-request ref ("git fetch origin
	// pull/${{ github.event.number }}/head:pr") or a head reference
	ghPRCheckout = regexp.MustCompile(`\bgh\s+pr\s+checkout\b`)
	gitFetchCmd  = regexp.MustCompile(`\bgit\b[^|;&]*\b(fetch|checkout|switch|reset|clone|pull|worktree)\b`)
	pullRef      = regexp.MustCompile(`\bpull/(\$\{\{[^}]*\}\}|[^\s/]+)/(head|merge)\b`)
	// downloads of an artifact of another run (under workflow_run: the run
	// that triggered the workflow)
	ghRunDownload = regexp.MustCompile(`\bgh\s+run\s+download\b`)
	chained       = regexp.MustCompile(`(&&|;|\|\|)\s*\S`)
)

// laterCommand returns the line of the first command after position pos of
// line j of a script (0 if there is none).
func laterCommand(lines []string, j, pos, first int) int {
	if chained.MatchString(lines[j][pos:]) {
		return first + j
	}
	for k := j + 1; k < len(lines); k++ {
		if t := strings.TrimSpace(lines[k]); t != "" && !strings.HasPrefix(t, "#") {
			return first + k
		}
	}
	return 0
}

// injectionOf returns the first expression of s that interpolates
// attacker-controlled input.
func injectionOf(s string) string {
	for _, m := range expression.FindAllString(s, -1) {
		if untrusted.MatchString(m) {
			return m
		}
	}
	return ""
}

// Audit checks all workflow files below dir, the local actions they use and
// the other action definitions of the repository. It returns the findings, the
// files that were checked and the files that could not be read or parsed
// (problems make the CI part of the analysis incomplete).
func Audit(dir string) (findings []*model.Finding, files []string, problems []string) {
	wf := filepath.Join(dir, ".github", "workflows")
	entries, err := os.ReadDir(wf)
	if err != nil && !os.IsNotExist(err) {
		problems = append(problems, rel(dir, wf)+": "+err.Error())
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml") {
			files = append(files, filepath.Join(wf, e.Name()))
		}
	}
	sort.Strings(files)
	var refs []localRef
	for _, f := range files {
		fs, rs, err := auditGitHub(dir, f)
		if err != nil {
			problems = append(problems, rel(dir, f)+": "+err.Error())
		}
		findings = append(findings, fs...)
		refs = append(refs, rs...)
	}
	afs, afiles, aproblems := auditActions(dir, refs)
	findings, files, problems = append(findings, afs...), append(files, afiles...), append(problems, aproblems...)
	if gl := filepath.Join(dir, ".gitlab-ci.yml"); fileExists(gl) {
		files = append(files, gl)
		fs, err := auditGitLab(dir, gl)
		if err != nil {
			problems = append(problems, rel(dir, gl)+": "+err.Error())
		}
		findings = append(findings, fs...)
	}
	return findings, files, problems
}

// load parses a CI configuration file.
func load(file string) (*yaml.Node, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("cannot be parsed: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("cannot be parsed: not a YAML mapping")
	}
	return doc.Content[0], nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func rel(dir, f string) string {
	r, err := filepath.Rel(dir, f)
	if err != nil {
		return f
	}
	return filepath.ToSlash(r)
}

type ctx struct {
	file string
	out  []*model.Finding
}

// add records a finding once: a step that is reused through a YAML alias is
// reported at its anchored definition only.
func (c *ctx) add(rule, sev string, line int, title, detail string) *model.Finding {
	for _, f := range c.out {
		if f.Rule == rule && f.Line == line && f.Detail == detail {
			return f
		}
	}
	f := &model.Finding{
		ID: "SSCA-CI-" + rule, Kind: model.KindCI, Rule: rule, Severity: sev,
		Title: title, Detail: detail, File: c.file, Line: line, Module: "M5",
	}
	c.out = append(c.out, f)
	return f
}

// addRef records an action-reference finding with the kind of reference
// ("tag" for a tag or branch, "none" without any version, "image" for a
// container without a digest); policies read it as ci.action_ref_type.
func (c *ctx) addRef(refType, sev string, line int, title, detail string) {
	f := c.add("unpinned-action", sev, line, title, detail)
	f.Evidence = map[string]any{"action_ref_type": refType}
}

// deref follows a YAML alias ("steps: *common") to the anchored node.
func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// mapGet returns the value of key in a mapping, following aliases and merge
// keys ("<<: *defaults"); an explicit key wins over a merged one.
func mapGet(n *yaml.Node, key string) *yaml.Node {
	return mapGetDepth(n, key, 0)
}

func mapGetDepth(n *yaml.Node, key string, depth int) *yaml.Node {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode || depth > 10 {
		return nil
	}
	var merged []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value == key && k.Tag != "!!merge" {
			return deref(v)
		}
		if k.Tag == "!!merge" {
			if v = deref(v); v != nil && v.Kind == yaml.SequenceNode {
				merged = append(merged, v.Content...)
			} else {
				merged = append(merged, v)
			}
		}
	}
	for _, m := range merged {
		if v := mapGetDepth(m, key, depth+1); v != nil {
			return v
		}
	}
	return nil
}

// items returns the elements of a sequence, following aliases.
func items(n *yaml.Node) []*yaml.Node {
	n = deref(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]*yaml.Node, len(n.Content))
	for i, x := range n.Content {
		out[i] = deref(x)
	}
	return out
}

// triggerLine returns the line where one of the given triggers is declared
// ("on: x", "on: [x, y]" or a mapping).
func triggerLine(on *yaml.Node, names ...string) int {
	if on == nil {
		return 1
	}
	for _, x := range on.Content {
		for _, n := range names {
			if x.Value == n {
				return x.Line
			}
		}
	}
	return on.Line
}

// scriptLine returns the line of the first script line of a scalar: block
// scalars ("run: |") start on the line after the key.
func scriptLine(n *yaml.Node) int {
	if n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return n.Line + 1
	}
	return n.Line
}

// flags describe the context the steps run in.
type flags struct {
	privileged  bool // pull_request_target, workflow_run or issue_comment: secrets and a write token
	workflowRun bool // artifacts of another run are those of the triggering run
}

// localRef is a "uses: ./path" step: a local action that is audited with the
// flags of the workflow that runs it.
type localRef struct {
	path, from string
	line       int
	fl         flags
}

func auditGitHub(dir, file string) ([]*model.Finding, []localRef, error) {
	c := &ctx{file: rel(dir, file)}
	root, err := load(file)
	if err != nil {
		return nil, nil, err
	}
	// triggers
	on := mapGet(root, "on")
	if on == nil {
		on = mapGet(root, "true") // YAML 1.1 parses "on" as boolean
	}
	on = deref(on)
	triggers := map[string]bool{}
	if on != nil {
		switch on.Kind {
		case yaml.ScalarNode:
			triggers[on.Value] = true
		case yaml.SequenceNode:
			for _, x := range on.Content {
				triggers[x.Value] = true
			}
		case yaml.MappingNode:
			for i := 0; i < len(on.Content); i += 2 {
				triggers[on.Content[i].Value] = true
			}
		}
	}
	// issue_comment runs in the context of the base repository like
	// pull_request_target (secrets, write token), also for comments on pull
	// requests from forks
	fl := flags{privileged: triggers["pull_request_target"] || triggers["workflow_run"] || triggers["issue_comment"],
		workflowRun: triggers["workflow_run"]}
	// permissions
	perms := mapGet(root, "permissions")
	if perms == nil {
		jobsHavePerms := true
		for _, j := range jobs(root) {
			if mapGet(j.node, "permissions") == nil {
				jobsHavePerms = false
			}
		}
		if !jobsHavePerms {
			c.add("token-permissions", model.SevMedium, 1, "No explicit token permissions",
				"GITHUB_TOKEN gets the repository default, which may include write access; declare 'permissions:' with least privilege")
		}
	} else if perms.Kind == yaml.ScalarNode && perms.Value == "write-all" {
		c.add("token-permissions", model.SevHigh, perms.Line, "Workflow grants write-all token permissions", writeAll)
	}
	var refs []localRef
	for _, j := range jobs(root) {
		if p := mapGet(j.node, "permissions"); p != nil && p.Kind == yaml.ScalarNode && p.Value == "write-all" {
			c.add("token-permissions", model.SevHigh, p.Line, "Job "+j.name+" grants write-all token permissions", writeAll)
		}
		if u := mapGet(j.node, "uses"); u != nil { // reusable workflow
			c.checkUses(u.Value, u.Line)
			if s := mapGet(j.node, "secrets"); s != nil && s.Kind == yaml.ScalarNode && s.Value == "inherit" {
				c.add("secrets-inherit", model.SevLow, s.Line, "Reusable workflow inherits all secrets", u.Value)
			}
		}
		c.checkJobImages(j)
		refs = append(refs, c.auditSteps(items(mapGet(j.node, "steps")), fl)...)
	}
	if fl.privileged {
		c.add("privileged-trigger", model.SevMedium, triggerLine(on, "pull_request_target", "workflow_run", "issue_comment"),
			"Workflow uses a privileged trigger", "pull_request_target, workflow_run and issue_comment have access to secrets; make sure no untrusted code is executed")
	}
	return c.out, refs, nil
}

// checkJobImages reports job containers and service containers that are not
// pinned to a digest: every step of the job runs in the container image.
func (c *ctx) checkJobImages(j job) {
	check := func(n *yaml.Node, what string) {
		if n != nil && n.Kind == yaml.MappingNode {
			n = mapGet(n, "image")
		}
		if n == nil || n.Kind != yaml.ScalarNode || n.Value == "" || strings.Contains(n.Value, "${{") || strings.Contains(n.Value, "@sha256:") {
			return
		}
		c.addRef("image", model.SevMedium, n.Line, what+" image not pinned to a digest",
			n.Value+": pin to a digest (image@sha256:...); a tag can be moved to another image")
	}
	check(mapGet(j.node, "container"), "Job "+j.name+" container")
	if sv := mapGet(j.node, "services"); sv != nil && sv.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(sv.Content); i += 2 {
			check(deref(sv.Content[i+1]), "Service container "+sv.Content[i].Value)
		}
	}
}

// auditSteps checks the steps of a job or of a composite action and returns
// the local actions they use.
func (c *ctx) auditSteps(steps []*yaml.Node, fl flags) []localRef {
	var refs []localRef
	artifact, artifactStep := 0, -1 // download of an artifact of the triggering run: line and step
	artifactUse := 0                // first later line that runs commands
	for i, st := range steps {
		executes, downloads := false, 0
		if u := mapGet(st, "uses"); u != nil {
			c.checkUses(u.Value, u.Line)
			if strings.HasPrefix(u.Value, "./") {
				refs = append(refs, localRef{path: u.Value, from: c.file, line: u.Line, fl: fl})
				executes = true
			}
			w := mapGet(st, "with")
			if fl.privileged && strings.HasPrefix(u.Value, "actions/checkout") {
				for _, key := range []string{"ref", "repository"} {
					if r := mapGet(w, key); r != nil && headCheckout.MatchString(r.Value) {
						c.untrustedCheckout(r.Line, r.Value)
						break
					}
				}
			}
			// actions/github-script evaluates its script input as JavaScript
			if strings.HasPrefix(u.Value, "actions/github-script") {
				if sc := mapGet(w, "script"); sc != nil {
					c.checkInjection(sc.Value, scriptLine(sc))
					if strings.Contains(sc.Value, "downloadArtifact") {
						downloads = u.Line
					}
				}
				executes = true
			}
			if downloadsForeignArtifact(u.Value, w) {
				downloads = u.Line
			}
		}
		if r := mapGet(st, "run"); r != nil {
			c.checkRun(r.Value, scriptLine(r), fl)
			executes = true
			lines := strings.Split(r.Value, "\n")
			for j, l := range lines {
				if loc := ghRunDownload.FindStringIndex(l); loc != nil {
					downloads, executes = scriptLine(r)+j, false
					// commands of the same script after the download
					if fl.workflowRun && artifact == 0 {
						artifactUse = laterCommand(lines, j, loc[1], scriptLine(r))
					}
					break
				}
			}
		}
		if fl.workflowRun && artifact == 0 && downloads > 0 {
			artifact, artifactStep = downloads, i
		} else if artifact > 0 && executes && artifactUse == 0 && i > artifactStep {
			artifactUse = st.Line
		}
	}
	if artifact > 0 {
		const why = "workflow_run runs with secrets and a write token, but the artifact was produced by the triggering run, which may be the code of a fork pull request; treat its content as untrusted data and never execute it (T-05, T-07)"
		if artifactUse > 0 {
			c.add("untrusted-artifact", model.SevHigh, artifact, "Privileged workflow runs commands after downloading an artifact of the triggering run",
				fmt.Sprintf("%s; line %d runs commands after the download", why, artifactUse))
		} else {
			c.add("untrusted-artifact", model.SevMedium, artifact, "Privileged workflow downloads an artifact of the triggering run", why)
		}
	}
	return refs
}

// downloadsForeignArtifact reports whether a step downloads an artifact of
// another workflow run: actions/download-artifact with a run-id, or an action
// made for that purpose.
func downloadsForeignArtifact(uses string, with *yaml.Node) bool {
	switch {
	case strings.HasPrefix(uses, "actions/download-artifact"):
		return mapGet(with, "run-id") != nil
	case strings.HasPrefix(uses, "dawidd6/action-download-artifact"):
		return true
	}
	return false
}

func (c *ctx) untrustedCheckout(line int, what string) {
	c.add("untrusted-checkout", model.SevCritical, line,
		"Privileged trigger checks out untrusted pull-request code",
		"pull_request_target, workflow_run and issue_comment run with secrets; checking out the code of the pull request or of the triggering run lets an attacker run code with them (T-05, T-07): "+what)
}

// auditActions checks the local actions: those used by the workflows
// ("uses: ./path", also from other local actions) with the flags of the
// workflows that use them, and the other action.yml files of .github and of
// the repository root (actions published from the repository).
func auditActions(dir string, refs []localRef) (findings []*model.Finding, files, problems []string) {
	type entry struct{ fl flags }
	actions := map[string]*entry{} // action.yml path -> flags
	var order []string
	queue := append([]localRef{}, refs...)
	resolve := func(p string) string {
		d := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(p, "./")))
		for _, n := range []string{"action.yml", "action.yaml"} {
			if f := filepath.Join(d, n); fileExists(f) {
				return f
			}
		}
		return ""
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		f := resolve(r.path)
		if f == "" {
			problems = append(problems, fmt.Sprintf("%s:%d: local action %s has no action.yml in the repository and was not audited", r.from, r.line, r.path))
			continue
		}
		e := actions[f]
		if e == nil {
			e = &entry{}
			actions[f] = e
			order = append(order, f)
		} else if merged := (flags{e.fl.privileged || r.fl.privileged, e.fl.workflowRun || r.fl.workflowRun}); merged == e.fl {
			continue // already audited in this context
		}
		e.fl.privileged = e.fl.privileged || r.fl.privileged
		e.fl.workflowRun = e.fl.workflowRun || r.fl.workflowRun
		// the actions used by this action get its flags
		if sub, _, err := auditAction(dir, f, e.fl); err == nil {
			queue = append(queue, sub...)
		}
	}
	// action definitions that no workflow of the repository uses
	var other []string
	gh := filepath.Join(dir, ".github")
	filepath.WalkDir(gh, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && p == filepath.Join(gh, "workflows") {
			return filepath.SkipDir
		}
		if !d.IsDir() && (d.Name() == "action.yml" || d.Name() == "action.yaml") {
			other = append(other, p)
		}
		return nil
	})
	for _, n := range []string{"action.yml", "action.yaml"} {
		if f := filepath.Join(dir, n); fileExists(f) {
			other = append(other, f)
		}
	}
	for _, f := range other {
		if actions[f] == nil {
			actions[f] = &entry{}
			order = append(order, f)
		}
	}
	sort.Strings(order)
	for _, f := range order {
		files = append(files, f)
		_, fs, err := auditAction(dir, f, actions[f].fl)
		if err != nil {
			problems = append(problems, rel(dir, f)+": "+err.Error())
		}
		findings = append(findings, fs...)
	}
	return findings, files, problems
}

// auditAction checks one action definition: the steps of a composite action
// and the image of a container action.
func auditAction(dir, file string, fl flags) ([]localRef, []*model.Finding, error) {
	c := &ctx{file: rel(dir, file)}
	root, err := load(file)
	if err != nil {
		return nil, nil, err
	}
	runs := mapGet(root, "runs")
	using := mapGet(runs, "using")
	if runs == nil || using == nil {
		return nil, nil, fmt.Errorf("not an action definition (no runs.using)")
	}
	var refs []localRef
	switch using.Value {
	case "composite":
		refs = c.auditSteps(items(mapGet(runs, "steps")), fl)
	case "docker":
		if img := mapGet(runs, "image"); img != nil && strings.HasPrefix(img.Value, "docker://") {
			c.checkUses(img.Value, img.Line)
		}
	}
	return refs, c.out, nil
}

const writeAll = "every scope of GITHUB_TOKEN gets write access; declare only the permissions the jobs need"

type job struct {
	name string
	node *yaml.Node
}

func jobs(root *yaml.Node) []job {
	js := mapGet(root, "jobs")
	if js == nil || js.Kind != yaml.MappingNode {
		return nil
	}
	var out []job
	for i := 0; i+1 < len(js.Content); i += 2 {
		out = append(out, job{js.Content[i].Value, deref(js.Content[i+1])})
	}
	return out
}

// checkUses reports actions not pinned to a full commit SHA (T-07).
func (c *ctx) checkUses(uses string, line int) {
	if strings.HasPrefix(uses, "./") {
		return
	}
	if strings.HasPrefix(uses, "docker://") {
		if !strings.Contains(uses, "@sha256:") {
			c.addRef("image", model.SevMedium, line, "Container action not pinned to a digest", uses)
		}
		return
	}
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		c.addRef("none", model.SevHigh, line, "Action used without any version", uses)
		return
	}
	ref := uses[at+1:]
	if !shaRef.MatchString(ref) {
		sev := model.SevHigh
		owner := strings.Split(uses, "/")[0]
		if owner == "actions" || owner == "github" {
			sev = model.SevMedium // first-party actions are lower risk but still mutable
		}
		c.addRef("tag", sev, line, "Action referenced by a mutable tag or branch",
			fmt.Sprintf("%s: pin to a full commit SHA (tag %q can be moved, as in the tj-actions and trivy-action incidents)", uses, ref))
	}
}

// checkInjection checks a script that is not run by a shell (the JavaScript
// of actions/github-script) for interpolated untrusted input.
func (c *ctx) checkInjection(script string, first int) {
	for i, l := range strings.Split(script, "\n") {
		if m := injectionOf(l); m != "" {
			c.add("script-injection", model.SevHigh, first+i, "Untrusted input interpolated into a script", m)
		}
	}
}

// checkRun checks a shell script whose first line is on line first.
func (c *ctx) checkRun(run string, first int, fl flags) {
	for i, l := range strings.Split(run, "\n") {
		ln := first + i
		t := strings.TrimSpace(l)
		if fl.privileged && (ghPRCheckout.MatchString(t) || gitFetchCmd.MatchString(t) && (pullRef.MatchString(t) || headCheckout.MatchString(t))) {
			c.untrustedCheckout(ln, t)
		}
		if installCmd.MatchString(t) && !strings.Contains(t, "--ignore-scripts") {
			c.add("install-scripts", model.SevMedium, ln, "Package installation runs install-time scripts",
				t+" — add --ignore-scripts (or an allowlist) so that dependency lifecycle scripts cannot run in CI (T-05)")
		}
		if m := injectionOf(t); m != "" {
			c.add("script-injection", model.SevHigh, ln, "Untrusted input interpolated into a shell command", m)
		}
		if pipeToShell.MatchString(t) {
			c.add("pipe-to-shell", model.SevMedium, ln, "Remote script piped into a shell", t)
		}
		if strings.Contains(t, "pip install") && !strings.Contains(t, "--require-hashes") && !strings.Contains(t, "-r ") && !strings.Contains(t, "--upgrade pip") {
			c.add("unpinned-install", model.SevLow, ln, "pip install without a lockfile or hashes", t)
		}
	}
}

func auditGitLab(dir, file string) ([]*model.Finding, error) {
	c := &ctx{file: rel(dir, file)}
	root, err := load(file)
	if err != nil {
		return nil, err
	}
	// each node is visited once: anchors (".defaults: &d") are reported at
	// their definition, and nested aliases cannot multiply the work
	visited := map[*yaml.Node]bool{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		n = deref(n)
		if n == nil || visited[n] {
			return
		}
		visited[n] = true
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i].Value, deref(n.Content[i+1])
				switch {
				case k == "image":
					img := v
					if v.Kind == yaml.MappingNode { // image: {name: ..., entrypoint: ...}
						img = mapGet(v, "name")
					}
					if img != nil && img.Kind == yaml.ScalarNode && !strings.Contains(img.Value, "@sha256:") {
						c.add("unpinned-image", model.SevLow, img.Line, "CI image not pinned to a digest", img.Value)
					}
				case k == "remote" && v.Kind == yaml.ScalarNode:
					c.add("remote-include", model.SevMedium, v.Line, "Remote CI configuration included", v.Value)
				case k == "script" || k == "before_script" || k == "after_script":
					if v.Kind == yaml.ScalarNode {
						c.checkRun(v.Value, scriptLine(v), flags{})
					}
					for _, s := range items(v) {
						if s.Kind == yaml.ScalarNode {
							c.checkRun(s.Value, scriptLine(s), flags{})
						}
					}
				}
				walk(v)
			}
			return
		}
		for _, x := range n.Content {
			walk(x)
		}
	}
	walk(root)
	return c.out, nil
}
