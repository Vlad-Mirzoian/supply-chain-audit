# ssca usage reference

Detailed behaviour of the `ssca` commands. For installation and a quick start
see the [README](../README.md). Every command prints its flags with `-h`.

- [Exit codes and incomplete results](#exit-codes-and-incomplete-results)
- [Commands](#commands)
- [Dependency scopes](#dependency-scopes)
- [Ecosystems and lockfiles](#ecosystems-and-lockfiles)
- [Integrity and provenance](#integrity-and-provenance)
- [Vulnerabilities and VEX](#vulnerabilities-and-vex)
- [Malicious-package signals and typosquatting](#malicious-package-signals-and-typosquatting)
- [CI audit](#ci-audit)
- [Policy](#policy)
- [Data cache and offline snapshots](#data-cache-and-offline-snapshots)
- [Output files and reproducibility](#output-files-and-reproducibility)
- [Environment variables](#environment-variables)

## Exit codes and incomplete results

| Code | Meaning |
|---|---|
| 0 | no policy violation (or `-h`) |
| 1 | policy violation: the build is blocked |
| 2 | the analysis is incomplete and nothing was violated |
| 3 | usage error: bad flag, flag after the arguments, missing directory or one without project files, unknown `--ecosystem`, invalid policy or VEX document |
| 4 | self-check failure: a file of a sealed data snapshot was changed |

The subcommands print text for people and give scripts these exit codes;
`graph`, `diff`, `sbom --validate` and `verify-artifact` also have `--json`.
Flags go before the arguments (`ssca scan --offline .`, not `ssca scan .
--offline`): a flag after them is a usage error, because it would otherwise be
ignored.

An incomplete result is not reported as a pass, unless the policy of `scan`
sets `thresholds.incomplete_analysis: warn` (then a run without violations
passes and the report still lists the reasons). It says so at the end of the
first line ("— INCOMPLETE (n reasons, see below)") and ends with exit code 2;
this includes `sbom`, whose documents then carry the reasons (a CycloneDX
composition `incomplete` of the root plus `ssca:incomplete` properties, the
SPDX creation comment). The printed summary and `summary.md` list the reasons
in a compact form: duplicates (one per Maven module) are dropped and data
missing from the offline snapshot is folded into one line that names the first
packages; `report.json` and `graph --json` keep every reason.

Causes of an incomplete analysis include: registry or metadata sources that
could not be read (one reason per source with the number of components), a
dependency that cannot be resolved, a lockfile that is out of sync with its
manifest, requirements that cannot be analysed, a CI workflow that cannot be
parsed, a local action without `action.yml`, and a policy condition that fails
at run time. The answer "not found" from a registry is not a failure.

## Commands

### scan

    ssca scan [flags] [dir]

Full audit: dependency graph, SBOMs, vulnerabilities, integrity and
provenance, malicious-package signals, CI audit, risk scores and the policy
decision. Writes its reports to `--out` (default `ssca-out`).

| Flag | Meaning |
|---|---|
| `--out DIR` | output directory for reports and the evidence bundle |
| `--policy FILE` | policy file; `builtin` forces the built-in policy |
| `--vex FILE` | VEX document (OpenVEX or CycloneDX), repeatable |
| `--offline` | use only the cached data snapshot, no network |
| `--cache DIR` | cache / data snapshot directory |
| `--now TIME` | evaluation time (RFC 3339), for reproducible runs |
| `--include-dev` | also report vulnerabilities of development and test dependencies |
| `--runtime-only` | leave development and test dependencies out entirely |
| `--ecosystem E` | audit only `npm`, `pypi` or `maven` |
| `--resolve` | ignore lockfiles and resolve from manifests |
| `--reachability` | package-level reachability analysis (downloads archives) |
| `--provenance=false` | skip Sigstore verification of npm provenance and PEP 740 attestations |
| `--no-metadata` | skip registry metadata (health and malice signals) |
| `--quiet` | do not print the summary |

### graph

    ssca graph [--tree] [--depth N] [--json] [dir]

Prints the dependency graph summary (components, edges, cycles, conflicts,
depth and scope distribution). `--tree [--depth N]` prints the dependency tree
with repeated subtrees shown once (not with `--json`, which lists every
component with its depth and scope). `graph` ends with exit code 2 when the graph
is incomplete (also with `--json`) and marks the first line of its summary with
`INCOMPLETE`. A conflict is a dependency whose versions are known but none
satisfies the range; a dependency whose data could not be fetched is only a
reason of incompleteness (an unresolved npm optional dependency is a note).
Without a lockfile the text output warns as `sbom` does (see below).

### sbom

    ssca sbom [--out DIR] [--no-enrich] [dir]
    ssca sbom --validate FILE [--min-score N] [--json]

Writes CycloneDX 1.6 and SPDX 2.3 documents with the CISA minimum elements. By
default the SBOM is enriched from the registries, with the same metadata as a
`scan`: suppliers, licenses, the SHA-1 that Maven Central publishes next to a
jar and, for PyPI packages without a lockfile hash, the SHA-256 of every file
of the release as the PyPI Simple API lists it (with `--offline` from the data
snapshot; what is not there stays empty). `--no-enrich` writes only what the
lockfiles and manifests record and needs no network: fast, but without
suppliers and licenses, and without hashes for projects that have no lockfile,
so that `--validate` rejects most such SBOMs. (`--enrich` is still accepted; it
is the default.) The supplier is written only when the package metadata
declares one. All hashes recorded by the lockfile are kept; hashes from the
registry are used only when the lockfile records none, and only in the SBOM:
the integrity check (M3) compares the lockfile with the registry.

When the npm or PyPI dependencies come without a lockfile (`requirements.txt`,
`pyproject.toml`, `package.json` alone, or `--resolve`), `sbom`, `graph` and
`scan` (on standard error) warn: their hashes are not pinned by the project,
and every version that the manifests do not pin exactly, transitive ones
included, is resolved at the time of the run and can differ from what an
installation gets. For npm such a graph is also incomplete (exit code 2); for
PyPI the warning is the only sign. A lockfile pins both (`uv lock`, `poetry lock`,
`pip-compile --generate-hashes`, `npm install --package-lock-only`); a
requirements file that pins every package with `--hash` counts as locked. Maven
has no lockfile and is not named.

In SPDX 2.3, which has no field for it, the generation context (the CycloneDX
lifecycle phase, `pre-build` for an SBOM made from lockfiles and manifests) is
stated in the creation comment ("Generation context: pre-build."), next to the
reasons of an incomplete analysis.

`--validate` scores an existing SBOM (of any tool) against the 11 CISA minimum
elements and decides: exit code 2 if the SBOM states that it is incomplete (the
dependency relationships element then counts as not met), 1 if it has no
components or the score is below `--min-score` (default 80 %, at most two
elements missing), otherwise 0. `--min-score` and `--json` apply only to
`--validate`, and the flags of SBOM generation (`--out`, `--ecosystem`,
`--runtime-only`, `--resolve`, `--no-enrich`) and a project directory are
usage errors with it.

### diff

    ssca diff [--mode M] [--json] A.json B.json

Compares two SBOMs with purl normalisation (PEP 503 for Python names) and
reports added, removed and changed components and the Jaccard similarity.
Modes: `declared-vs-observed` (default), `release-vs-release`,
`vendor-vs-generated`. Exit code 1 if a change is high or critical (a phantom
component, changed provenance, a hash mismatch of the same version);
otherwise 2 if one of the SBOMs states that it is incomplete (its missing
packages may be no real change; `--json` lists the reasons under
`incomplete`), else 0.

### typosquat

    ssca typosquat [--ecosystem npm|pypi] [--top N] NAME...

Checks package names offline against the built-in dictionary of popular
packages, scoring them as `scan` does. Exit code 1 if a name looks like a
popular package.

### ci-audit

    ssca ci-audit [dir]

Audits GitHub Actions workflows and GitLab CI files; see [CI audit](#ci-audit).

### verify-artifact

    ssca verify-artifact [--bundle FILE] [--repo owner/name] [--builder IDS] [--sha512 HEX] [--json] ARTIFACT

Verifies a file against a Sigstore bundle (default `<artifact>.sigstore.json`).
`--repo` names the expected GitHub repository of the signing workflow;
`--builder` replaces the list of trusted builders (see
[Integrity and provenance](#integrity-and-provenance)).

### cache

    ssca cache [--cache DIR] [--json]
    ssca cache seal [--cache DIR]

See [Data cache and offline snapshots](#data-cache-and-offline-snapshots).

`-h` prints the usage of any command and exits with 0.

## Dependency scopes

Every component carries the scope in which it is used: `runtime`, `optional`,
`provided`, `extra`, `development` or `test`.

The graph always holds development and test dependencies (npm
`devDependencies`, uv/PEP 735 dependency groups, poetry groups, the `develop`
section of Pipfile.lock, Maven `test` scope, Python development and test
requirement files such as `requirements-dev.txt`, `requirements-test.txt`,
`requirements/dev.txt` or `docs/requirements.txt`) next to the runtime,
optional and provided ones, and the packages that only an extra of the Python
project itself needs (scope `extra`: pip, uv and Poetry install extras only on
request, so they are treated like development dependencies). A package that a
runtime dependency also needs is runtime.

- **Checked in every scope:** known-malicious versions (OSV `MAL-` records),
  lockfile hashes and sources, and the malicious-package indicators, because
  the install scripts of development tools run on developer machines and in CI,
  where tokens with publishing rights are available.
- **Vulnerabilities** of development and test dependencies are reported only
  with `--include-dev`, with the exposure factor c = 0.6 (development) or 0.3
  (test). Optional and provided components count as production code (c = 1.0
  direct, 0.8 transitive).
- **`--runtime-only`** leaves development and test dependencies out of the
  graph, the SBOM and every check (the runtime view that other scanners report).
- **`dev_heuristics: false`** in the policy limits registry metadata and
  indicators to the production scopes.
- **Reachability analysis** covers production packages only.

Development requirement files are resolved with the runtime versions fixed, so
the production part of the graph does not change; `-e .` is ignored there, and
a pin that conflicts with the runtime requirements makes the analysis
incomplete.

The `dev`/`optional` flags of package-lock.json are checked against its
`dependencies`/`optionalDependencies` chains: a package marked `dev` that a
production package needs keeps the derived scope (also with `--runtime-only`)
and is reported as `SSCA-LOCKFILE-SCOPE`; peer dependencies are not used for
this check. An entry of package-lock.json that no dependency requires is
installed by `npm ci` anyway: it is kept, attached to the project, and reported
as `SSCA-LOCKFILE-EXTRANEOUS`.

In the SBOMs, development and test components carry the CycloneDX scope
`excluded` (npm packages also `cdx:npm:package:development`), and SPDX relates
them with `DEV_DEPENDENCY_OF` or `TEST_DEPENDENCY_OF` instead of `DEPENDS_ON`.
Policy rules can test `component.production` (runtime, optional or provided).

## Ecosystems and lockfiles

| Ecosystem | Inputs |
|---|---|
| npm | package-lock.json (v1–v3), yarn.lock (v1 and berry), pnpm-lock.yaml; workspaces |
| PyPI | uv.lock, poetry.lock, Pipfile.lock, requirements files (with `-c` constraints), pyproject.toml |
| Maven | pom.xml with parents, BOM imports, properties and multi-module projects |

A directory with several ecosystems (e.g. package.json next to pyproject.toml)
is audited as one project; `--ecosystem` restricts the audit to one of them.
The root of such a project is the project itself, a generic component named
after the directory (`pkg:generic/NAME`, with the version that all manifests
state if they agree), not the package of one of its ecosystems.
`--resolve` ignores lockfiles and resolves versions from the manifests.

A lockfile must lock every dependency it is meant to lock; otherwise it is out
of sync and the analysis is incomplete:

- **npm.** A dependency declared in package.json, or required by a locked
  package, that has no entry in package-lock.json, yarn.lock or pnpm-lock.yaml
  (optional and peer dependencies may be missing; the yarn `resolutions` field
  and yarn 4 catalogs from `.yarnrc.yml` are applied). The same holds for a
  direct dependency that package-lock.json locks outside the SemVer range of
  package.json (`npm ci` refuses such a file; tags, aliases, git, file, link
  and workspace references are not ranges), for a pnpm-lock.yaml specifier that
  differs from package.json (overrides recorded in the lockfile are accepted)
  and for a `link` entry that points to a folder the lockfile does not
  describe. A package-lock.json entry without a version makes the analysis
  incomplete. The project's own dependencies come from package.json; a missing
  or different root entry of package-lock.json is a note. A yarn.lock that is
  not a lockfile is an error.
- **Python.** A dependency declared in pyproject.toml (also dependency groups
  and extras unless `--runtime-only`) or in the Pipfile that uv.lock,
  poetry.lock or Pipfile.lock does not lock (for uv.lock the requirements that
  uv recorded for the project are compared). Requirements that cannot be
  analysed (editable, VCS, URL or local-path lines) and a lockfile package that
  comes from git, a URL or a local path also make the analysis incomplete.
- **Maven.** A dependency of the project whose coordinates use a property that
  no POM defines makes the analysis incomplete (Maven stops); in the POM of a
  dependency such an entry is left out with a note, as Maven does.

A dependency that cannot be resolved (no version in range, registry
unreachable, missing pom version) makes the analysis incomplete; only npm
optional dependencies may be missing.

## Integrity and provenance

**Lockfile hashes.** Every lockfile hash is compared with the registry for each
algorithm both record (npm: sha512 with `dist.integrity`, sha1 with
`dist.shasum`; PyPI: sha256). Each component records the outcome in
`hash_check` (`verified`, `mismatch`, `no-lockfile-hash`, `other-source`,
`no-registry-hash`, `not-on-registry`, `unavailable`), which rules can read as
`component.hash_check`; `report.json` counts the outcomes and the summary
states how many hashes were verified. Registry data that cannot be fetched
makes the analysis incomplete.

**Package sources.** An npm package that the lockfile downloads from anywhere
but the public registry (another host, git, a local path) is an integrity
finding (`SSCA-LOCKFILE-SOURCE`), as is a registry URL that names another
package or version. Mirrors are listed in the policy
(`registries: [https://...]`), the organisation's registry in
`internal.registry`. Maven searches the repositories that a POM declares
(`<repositories>`, `<pluginRepositories>`, also in parents) before Maven
Central, so each one outside Central is an integrity finding of the project
(`SSCA-REPOSITORY-SOURCE`, high) unless the policy names it as a mirror or as
the internal registry; one over plain HTTP is critical in every case, and ssca
itself does not download from it.

**Sigstore.** npm provenance and PEP 740 attestations are verified against the
Sigstore trusted root. An online run gets the root through TUF and saves a copy
in the data snapshot. If TUF is unavailable the copy is not used: signatures
stay "not checked", the analysis is incomplete and the exit code is 2. Only an
explicit `--offline` uses the copy; `scan` reports then state its date and age
(`trusted_root_copy` in report.json, `summary.md`, the HTML report), and so
does `verify-artifact`.

**Announced but not served.** When the registry metadata announces an
attestation but the registry does not serve it (the attestation URL answers
404, or with a response that is not an attestation document, or with a
document without the announced SLSA statement; npm does this for some
trusted-publishing releases), nothing can be verified, and it is no evidence of
tampering: `scan` reports `SSCA-PROV-UNAVAILABLE` and the built-in policy warns
(`provenance-unavailable`). An attestation that is served and does not verify is
`SSCA-PROV-INVALID` and fails the build (`integrity-failure`); a package named
in `require_provenance` whose attestation is not served stays unsigned
(`unsigned-artifact`). report.json counts these packages in
`counters.provenance_not_served`.

**Trusted builders.** A verified SLSA statement must name a trusted builder
(policy `trusted_builders`; an entry ending in `/` or `@` is a prefix). Default:
the GitHub-hosted runners, the builder IDs of npm's SLSA v0.2 statements and
the GitLab.com runners, never a runner that the Fulcio certificate calls
self-hosted. GitHub artifact attestations (`actions/attest-build-provenance`)
name the building workflow as builder; by default they are trusted when the
certificate states a GitHub-hosted runner and the builder is the workflow that
signed the statement. Otherwise `scan` warns (`untrusted-builder`) and
`verify-artifact` fails (`--builder` replaces the list, e.g.
`--builder https://github.com/OWNER/REPO/.github/workflows/release.yml@` to
trust only one workflow).

## Vulnerabilities and VEX

Components are matched with OSV.dev; every advisory is checked again locally
with the version comparator of the ecosystem, aliases (e.g. GHSA and PYSEC
records of the same flaw) are merged, and findings are enriched with the CVSS
base score, the EPSS probability and the CISA KEV flag.

VEX documents (OpenVEX or CycloneDX, `--vex` or the policy key `vex:`) are
applied statement by statement: the latest statement about a vulnerability in a
component decides its status (statement `timestamp`, else the document
`timestamp`; CycloneDX `analysis.lastUpdated` or `updated`; equal or missing
times in the order of the files and statements), so a later `affected` or
`under_investigation` revokes an earlier `not_affected`. Only `not_affected`
and `fixed` suppress a finding; a suppressed finding stays in the report with
its justification, and every matched finding records `vex_status`. OpenVEX
vulnerability aliases are matched.

A statement without a product or vulnerability, with a missing or unknown
status, a `not_affected` without justification or impact statement (CycloneDX:
justification or detail), an unknown justification label or an unreadable
timestamp makes the document invalid (exit code 3), because a faulty document
could otherwise hide vulnerabilities silently.

## Malicious-package signals and typosquatting

Registry metadata (deps.dev, the npm registry and download counts, PyPI) gives
the release history, publishers, maintainers, install scripts, attestations
and new dependencies of each component. From these the suite computes
malicious-package indicators (e.g. publisher changed, install script added,
provenance regression, young new dependency, dependency confusion) that enter
the composite risk score. Metadata that could not be read for some components
makes the analysis incomplete, with one reason per source, and
`meta.unavailable` per component. Without the release history of deps.dev, the
history and the previous version come from the npm registry or the PyPI Simple
API.

A typosquat match is dismissed for an established package: first release at
least two years before the evaluation time, at least five releases, spread over
at least one year (release history from deps.dev, else from the registry; for
npm the downloads and maintainer checks follow). The dismissal is counted
(`typosquat_dismissed`) and named in the report notes; the components record
`first_release_at` and `releases`.

## CI audit

`ci-audit` (and `scan`) audits the workflows of `.github/workflows`, the local
actions they use (`uses: ./path`, also through another local action; composite
steps get the same checks as workflow steps, in the context of the workflows
that use them; container actions get the image check), the other `action.yml`
files of `.github` and of the repository root, and GitLab CI files. Every
finding carries a line number for SARIF. Steps shared through YAML anchors are
reported once, at their definition.

Checks:

- actions and container images referenced by a tag or branch instead of a full
  commit hash or digest, including job `container:` and `services:` images
  (`ci.action_ref_type` = `image`);
- privileged triggers (`pull_request_target`, `workflow_run`, `issue_comment`)
  that fetch pull-request code (`untrusted-checkout`: actions/checkout of a head
  reference or `refs/pull/`, `gh pr checkout`, git commands with `pull/N/head`
  or a head reference);
- under `workflow_run`, a download of an artifact of the triggering run
  (`untrusted-artifact`: `actions/download-artifact` with `run-id`,
  `dawidd6/action-download-artifact`, `gh run download`, `downloadArtifact` in
  github-script), high when later commands run, medium otherwise;
- missing or `write-all` token permissions;
- package installation without `--ignore-scripts`;
- untrusted input interpolated into shell commands or into the JavaScript of
  `actions/github-script` (recognised anywhere inside an expression);
- remote scripts piped into a shell.

A local action without `action.yml` in the repository and a workflow file that
cannot be read or parsed make the analysis incomplete.

The templates in [`docs/ci`](ci) (GitHub Actions and GitLab CI) follow these
rules: every action and image is pinned, the ssca binary is checked against its
hash and the data snapshot is kept in the CI cache; `ssca ci-audit` finds
nothing in them.

## Policy

Without `--policy`, `scan` uses `.ssca/policy.yaml` (or `.ssca/policy.yml`) of
the project directory when it exists and the built-in policy otherwise;
`--policy FILE` names another file and `--policy builtin` forces the built-in
policy. The summary, `report.json` (`policy`: source, SHA-256, discovered) and
`manifest.json` state which policy was applied.

The built-in policy fails on the critical risk band, warns on high, fails an
incomplete analysis and contains these rules: `known-malicious`,
`exploited-in-runtime`, `critical-reachable-cve`, `integrity-failure`,
`unsigned-artifact`, `dependency-confusion`, `provenance-regression` (fail) and
`untrusted-builder`, `provenance-unavailable`, `provenance-missing`, `cooldown`,
`unpinned-ci-action` (warn). Its source is `policy.Default` in
[`internal/policy/policy.go`](../internal/policy/policy.go) and a good
starting point for a project policy.

**Baseline rules.** Every policy also applies three rules that a policy file
cannot remove or weaken: `known-malicious`, `integrity-failure` and
`exploited-in-runtime` fail the build for a finding that no rule of the policy
failed or excepted. The policy file is part of the project, so the pull request
that adds a malicious or tampered package could otherwise also delete the rule
that stops it. Such violations are marked `baseline` in report.json and
"(baseline)" in the summary.

**Exceptions** accept one result: an exception must name a component, a
finding or a rule and has a reason and an expiry date; it is listed in the
report. An expired exception no longer applies and is listed as the warning
`exception-expired`, which does not change the exit code.

**Type checking.** Policy conditions are type-checked: a misspelt field or key
stops the scan with exit code 3 (`policy.Schema` lists the fields rules can
use). A CI rule on `ci.action_ref_type` applies only to unpinned-action
findings. A condition that fails at run time makes the decision incomplete.

Other keys: risk weights and thresholds, `registries` (mirrors),
`internal.registry`, `trusted_builders`, `dev_heuristics`, `vex:` (relative
paths are resolved against the directory of the policy file) and
`data_snapshot` (see below).

## Data cache and offline snapshots

Every response of a data source is cached on disk (default `$SSCA_CACHE`, else
the user cache directory, e.g. `~/.cache/ssca`). An online run reuses cached
responses younger than 24 h (`SSCA_CACHE_TTL`, a Go duration, changes this);
`--offline` uses only the cache and never goes to the network, so a run can be
repeated exactly from the same data snapshot. A request that a server rejects
with HTTP 429 or 5xx is retried up to three times; when the server says how
long to wait (`Retry-After`, seconds or a date), ssca waits that long, at most
60 s.

`ssca cache [--cache DIR] [--json]` shows the state of a cache directory: the
responses per data source, how many an online run would reuse, their dates and
sizes, and the saved trusted root. It only reads; the directory must be named
by `SSCA_CACHE` or `--cache`. Exit code 2 if some entries are damaged.

`ssca cache seal` freezes a snapshot: it writes `ssca-seal.json` with the
SHA-256 hash of every file and prints the seal ID. Offline runs on a sealed
cache check every file they read against it; a changed or added file stops the
run with exit code 4. A policy can require a sealed snapshot
(`data_snapshot: sealed`, or `data_snapshot: sha256:<seal id>` for one seal);
online runs refresh the cache and ignore the seal.

## Output files and reproducibility

`scan --out DIR` writes:

| File | Content |
|---|---|
| `summary.md` | the printed summary: decision, bands, violations, reasons of incompleteness |
| `report.json` | full machine-readable report: components, findings, scores, decision |
| `report.html` | the same as a standalone HTML page |
| `findings.sarif` | findings for GitHub code scanning |
| `sbom.cdx.json`, `sbom.spdx.json` | CycloneDX 1.6 and SPDX 2.3 SBOMs |
| `manifest.json` | evidence bundle: SHA-256 of every output, tool version, policy, data snapshot ID |

Each scan removes the outputs of an earlier run from `--out` before writing the
new ones, so `manifest.json` covers every ssca file in the directory. With
`--now` the manifest, the generated VEX document and `report.json`
(`evaluated_at`) carry that time, and two
runs over the same data snapshot give the same findings, scores, worst paths
and decision (only timings and the network cache counters may differ).

## Environment variables

| Variable | Default |
|---|---|
| `SSCA_CACHE` | cache directory (user cache dir + `/ssca`) |
| `SSCA_CACHE_TTL` | reuse time of cached responses in online runs (`24h`) |
| `SSCA_NPM_REGISTRY` | `https://registry.npmjs.org` |
| `SSCA_NPM_DOWNLOADS` | `https://api.npmjs.org/downloads/point/last-month/` |
| `SSCA_PYPI_INDEX` | `https://pypi.org` |
| `SSCA_MAVEN_REPO` | `https://repo1.maven.org/maven2` |
| `SSCA_DEPSDEV` | `https://api.deps.dev/v3` |
| `SSCA_OSV_API` | `https://api.osv.dev/v1` |
| `SSCA_EPSS` | `https://api.first.org/data/v1/epss` |
| `SSCA_KEV` | CISA KEV catalogue |

The registry and API variables point the suite at mirrors or test servers.
