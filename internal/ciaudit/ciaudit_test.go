package ciaudit

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

func writeWorkflows(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(wf, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const unsafeWorkflow = `name: ci
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: tj-actions/changed-files@v45
      - uses: actions/setup-node@0a44ba7841725637a19e28fa30b79a866c81b0a6
      - run: npm ci
      - run: echo "${{ github.event.pull_request.title }}"
`

func TestAuditFindsUnsafePatterns(t *testing.T) {
	dir := writeWorkflows(t, map[string]string{"ci.yml": unsafeWorkflow})
	fs, files, problems := Audit(dir)
	if len(files) != 1 || len(problems) != 0 {
		t.Fatalf("files: %v, problems: %v", files, problems)
	}
	got := map[string]int{}
	for _, f := range fs {
		got[f.Rule]++
	}
	want := map[string]int{"unpinned-action": 2, "untrusted-checkout": 1, "install-scripts": 1,
		"script-injection": 1, "token-permissions": 1, "privileged-trigger": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("rule %s: got %d findings, want %d (all: %v)", k, got[k], v, got)
		}
	}
}

// Findings must point at the line of the offending command, both for
// one-line "run:" steps and for block scalars ("run: |").
func TestAuditLineNumbers(t *testing.T) {
	dir := writeWorkflows(t, map[string]string{"x.yml": `on: [push, pull_request_target]
permissions: write-all
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
      - run: |
          echo start
          curl https://x.sh | bash
      - run: >-
          npm install
`})
	fs, _, problems := Audit(dir)
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	want := map[string]int{"script-injection": 7, "pipe-to-shell": 10, "install-scripts": 12,
		"privileged-trigger": 1, "token-permissions": 2}
	for _, f := range fs {
		if l, ok := want[f.Rule]; ok {
			if f.Line != l {
				t.Errorf("%s reported on line %d, want %d", f.Rule, f.Line, l)
			}
			delete(want, f.Rule)
		}
		if f.Rule == "token-permissions" && f.Detail == "" {
			t.Errorf("write-all finding has no detail")
		}
	}
	if len(want) != 0 {
		t.Errorf("missing findings: %v", want)
	}
}

// A workflow that cannot be parsed must not pass silently: it is reported as
// a problem, while the other files are still audited.
func TestAuditReportsUnparsableFiles(t *testing.T) {
	dir := writeWorkflows(t, map[string]string{
		"bad.yml":   "on: [push\n",
		"empty.yml": "",
		"ok.yml":    "on: push\npermissions: {}\njobs:\n  b:\n    steps:\n      - uses: some/action@main\n",
	})
	fs, files, problems := Audit(dir)
	if len(files) != 3 || len(problems) != 2 {
		t.Fatalf("files %v, problems %v", files, problems)
	}
	for _, p := range problems {
		if !strings.Contains(p, "cannot be parsed") {
			t.Errorf("problem %q", p)
		}
	}
	if len(fs) != 1 || fs[0].Rule != "unpinned-action" {
		t.Errorf("findings of ok.yml: %+v", fs)
	}
}

// Patterns of real attacks that the first rules missed: a workflow_run job
// that checks out the triggering run, injection through actions/github-script
// and through expressions with operators or indexes, and steps reused with a
// YAML anchor (reported once, at the anchor).
func TestWorkflowRunScriptInjectionAndAliases(t *testing.T) {
	dir := writeWorkflows(t, map[string]string{
		"wr.yml": `on:
  workflow_run:
    workflows: [build]
permissions:
  contents: read
jobs:
  deploy:
    steps:
      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
`,
		"issue.yml": `on: issues
permissions: {}
jobs:
  t:
    steps:
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: |
            const t = "${{ github.event.issue.title }}"
      - run: echo "${{ github.event.issue.title || 'none' }}"
      - run: echo "${{ github.event.commits[0].message }}"
      - run: echo "${{ github.event.issue.number }}"
`,
		"alias.yml": `on: push
permissions: {}
x-steps: &steps
  - uses: some/action@main
  - run: curl https://x.sh | bash
jobs:
  a:
    steps: *steps
  b:
    steps: *steps
`})
	fs, _, problems := Audit(dir)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	got := map[string]int{}
	for _, f := range fs {
		got[f.File[len(".github/workflows/"):]+":"+f.Rule+":"+strconv.Itoa(f.Line)]++
	}
	for _, w := range []string{
		"wr.yml:untrusted-checkout:11",
		"issue.yml:script-injection:9", "issue.yml:script-injection:10", "issue.yml:script-injection:11",
		"alias.yml:unpinned-action:4", "alias.yml:pipe-to-shell:5",
	} {
		if got[w] != 1 {
			t.Errorf("%s reported %d times, want once (all: %v)", w, got[w], got)
		}
	}
	if got["issue.yml:script-injection:12"] != 0 {
		t.Error("issue.number is not attacker-controlled text")
	}
	for _, f := range fs {
		if f.Rule == "unpinned-action" && f.Evidence["action_ref_type"] != "tag" {
			t.Errorf("unpinned action without ref type: %+v", f.Evidence)
		}
	}
}

// GitLab: anchors, image mappings and script strings.
func TestGitLabAnchors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte(`.defaults: &defaults
  image:
    name: node:20
  script: curl https://x.sh | sh
build:
  <<: *defaults
test:
  <<: *defaults
`), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, _, _ := Audit(dir)
	rules := map[string]int{}
	for _, f := range fs {
		rules[f.Rule]++
	}
	if rules["unpinned-image"] != 1 || rules["pipe-to-shell"] != 1 {
		t.Errorf("findings %v, want one unpinned-image and one pipe-to-shell", rules)
	}
}

// writeTree writes files relative to a new directory.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// ruleSet keys the findings as file:rule:line.
func ruleSet(fs []*model.Finding) map[string]int {
	got := map[string]int{}
	for _, f := range fs {
		got[f.File+":"+f.Rule+":"+strconv.Itoa(f.Line)]++
	}
	return got
}

func expect(t *testing.T, got map[string]int, want []string, absent []string) {
	t.Helper()
	for _, w := range want {
		if got[w] != 1 {
			t.Errorf("%s reported %d times, want once (all: %v)", w, got[w], got)
		}
	}
	for _, a := range absent {
		for k := range got {
			if strings.HasPrefix(k, a) {
				t.Errorf("unexpected finding %s", k)
			}
		}
	}
}

// Composite actions run their steps in the job that uses them: the steps of
// a local action are audited like workflow steps, in the context (trigger) of
// the workflows that use it, also through another local action; action
// definitions that no workflow uses and container actions are audited too; a
// local action that is not in the repository is a problem.
func TestCompositeActions(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".github/workflows/ci.yml": `on: push
permissions: {}
jobs:
  b:
    steps:
      - uses: ./.github/actions/setup
      - uses: ./.github/actions/missing
`,
		".github/workflows/prt.yml": `on: pull_request_target
permissions: {}
jobs:
  b:
    steps:
      - uses: ./tools/pr
`,
		".github/actions/setup/action.yml": `name: setup
runs:
  using: composite
  steps:
    - uses: evil/thing@main
    - run: curl https://x.sh | sh
      shell: bash
    - uses: ./.github/actions/inner
`,
		".github/actions/inner/action.yaml": `runs:
  using: composite
  steps:
    - run: echo "${{ github.event.head_commit.message }}"
      shell: bash
`,
		// used only by the pull_request_target workflow: checking out the
		// head of the pull request is an untrusted checkout there
		"tools/pr/action.yml": `runs:
  using: composite
  steps:
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      with:
        ref: ${{ github.event.pull_request.head.sha }}
    - run: gh pr checkout 1
      shell: bash
`,
		".github/actions/unused/action.yml": `runs:
  using: docker
  image: docker://alpine:3.19
`,
		"action.yml": `runs:
  using: node20
  main: index.js
`,
	})
	fs, files, problems := Audit(dir)
	if len(problems) != 1 || !strings.Contains(problems[0], ".github/workflows/ci.yml:7: local action ./.github/actions/missing has no action.yml") {
		t.Errorf("problems %v", problems)
	}
	if len(files) != 7 {
		t.Errorf("files %v", files)
	}
	expect(t, ruleSet(fs), []string{
		".github/actions/setup/action.yml:unpinned-action:5",
		".github/actions/setup/action.yml:pipe-to-shell:6",
		".github/actions/inner/action.yaml:script-injection:4",
		"tools/pr/action.yml:untrusted-checkout:6",
		"tools/pr/action.yml:untrusted-checkout:7",
		".github/actions/unused/action.yml:unpinned-action:3",
	}, []string{"action.yml:"})
	// a file that is not an action definition is a problem
	dir = writeTree(t, map[string]string{".github/actions/x/action.yml": "name: x\n"})
	if _, _, problems := Audit(dir); len(problems) != 1 || !strings.Contains(problems[0], "no runs.using") {
		t.Errorf("problems %v", problems)
	}
}

// issue_comment runs with secrets and a write token like pull_request_target;
// pull-request code fetched by gh, by git with a pull ref or a head
// reference, or by actions/checkout with refs/pull/ is untrusted there. The
// same commands under an unprivileged trigger are not reported.
func TestPullRequestCheckoutCommands(t *testing.T) {
	dir := writeWorkflows(t, map[string]string{
		"comment.yml": `on: issue_comment
permissions: {}
jobs:
  b:
    if: contains(github.event.comment.body, '/test')
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: gh pr checkout ${{ github.event.issue.number }}
`,
		"prt.yml": `on: pull_request_target
permissions: {}
jobs:
  b:
    steps:
      - run: |
          git fetch origin pull/${{ github.event.number }}/head:pr
          git checkout ${{ github.event.pull_request.head.sha }}
          git fetch origin +refs/pull/42/merge
          git log --oneline
`,
		"pr.yml": `on: pull_request
permissions: {}
jobs:
  b:
    steps:
      - run: gh pr checkout 1 && git fetch origin pull/1/head
`,
	})
	fs, _, problems := Audit(dir)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	w := ".github/workflows/"
	expect(t, ruleSet(fs), []string{
		w + "comment.yml:untrusted-checkout:9", w + "comment.yml:untrusted-checkout:10", w + "comment.yml:privileged-trigger:1",
		w + "prt.yml:untrusted-checkout:7", w + "prt.yml:untrusted-checkout:8", w + "prt.yml:untrusted-checkout:9",
	}, []string{w + "prt.yml:untrusted-checkout:10", w + "pr.yml:untrusted-checkout", w + "pr.yml:privileged-trigger"})
}

// workflow_run: an artifact of the triggering run is attacker-controlled when
// that run built a fork pull request; running commands after downloading it
// is high, the download alone medium. An artifact of the same run (no
// run-id) and other triggers are not reported.
func TestWorkflowRunArtifacts(t *testing.T) {
	const head = "on:\n  workflow_run:\n    workflows: [ci]\npermissions: {}\njobs:\n  b:\n    steps:\n"
	dir := writeWorkflows(t, map[string]string{
		"exec.yml": head + `      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16
        with: { run-id: "${{ github.event.workflow_run.id }}", github-token: "${{ secrets.GITHUB_TOKEN }}" }
      - run: bash ./build.sh
`,
		"only.yml": head + `      - uses: dawidd6/action-download-artifact@bf251b5aa9c2f7eeb574a96ee720e24f801b7c11
        with: { workflow: ci.yml }
`,
		"gh.yml": head + `      - run: |
          gh run download ${{ github.event.workflow_run.id }} -n dist
          ./dist/deploy.sh
`,
		"script.yml": head + `      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: |
            await github.rest.actions.downloadArtifact({owner: context.repo.owner, repo: context.repo.repo, artifact_id: 1, archive_format: 'zip'})
      - run: unzip pr.zip && cat NR >> $GITHUB_ENV
`,
		"same.yml": head + `      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16
      - run: bash ./build.sh
`,
		"push.yml": `on: push
permissions: {}
jobs:
  b:
    steps:
      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16
        with: { run-id: "123" }
      - run: bash ./build.sh
`,
	})
	fs, _, problems := Audit(dir)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	sev := map[string]string{}
	for _, f := range fs {
		if f.Rule == "untrusted-artifact" {
			sev[f.File[len(".github/workflows/"):]+":"+strconv.Itoa(f.Line)] = f.Severity
		}
	}
	want := map[string]string{"exec.yml:8": "high", "only.yml:8": "medium", "gh.yml:9": "high", "script.yml:8": "high"}
	for _, f := range fs {
		if f.Rule == "untrusted-artifact" && strings.HasSuffix(f.File, "gh.yml") && !strings.HasSuffix(f.Detail, "line 10 runs commands after the download") {
			t.Errorf("gh.yml: %s", f.Detail)
		}
	}
	if len(sev) != len(want) {
		t.Errorf("untrusted-artifact findings %v, want %v", sev, want)
	}
	for k, v := range want {
		if sev[k] != v {
			t.Errorf("%s: severity %q, want %q (all %v)", k, sev[k], v, sev)
		}
	}
}

// Job and service containers run the steps of the job: an image without a
// digest is an unpinned reference (policy field ci.action_ref_type = image).
func TestJobContainerImages(t *testing.T) {
	dir := writeWorkflows(t, map[string]string{"c.yml": `on: push
permissions: {}
jobs:
  a:
    container: node:20
    services:
      db: { image: "postgres:latest" }
      cache:
        image: redis@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    steps:
      - run: echo hi
  b:
    container:
      image: ghcr.io/x/y:1
    services:
      m: { image: "${{ matrix.image }}" }
  c:
    container:
      image: node@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
`})
	fs, _, _ := Audit(dir)
	w := ".github/workflows/c.yml:unpinned-action:"
	expect(t, ruleSet(fs), []string{w + "5", w + "7", w + "14"}, []string{w + "9", w + "16", w + "19"})
	for _, f := range fs {
		if f.Rule == "unpinned-action" && f.Evidence["action_ref_type"] != "image" {
			t.Errorf("container image finding without ref type image: %+v", f)
		}
	}
}

// The CI templates shipped with ssca (docs/ci, NFR-04) follow the rules that
// M5 checks: the auditor finds nothing in them.
func TestShippedTemplatesAreClean(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o755)
	for src, dst := range map[string]string{
		"../../docs/ci/github-workflow.yml": ".github/workflows/supply-chain.yml",
		"../../docs/ci/gitlab-ci.yml":       ".gitlab-ci.yml",
	} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, dst), b, 0o644)
	}
	fs, files, problems := Audit(dir)
	if len(files) != 2 || len(problems) != 0 {
		t.Fatalf("files %v, problems %v", files, problems)
	}
	for _, f := range fs {
		t.Errorf("%s:%d %s: %s", f.File, f.Line, f.Rule, f.Title)
	}
}
