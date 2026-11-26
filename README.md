# ssca — software supply-chain auditing suite

[![ci](https://github.com/Vlad-Mirzoian/supply-chain-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Vlad-Mirzoian/supply-chain-audit/actions/workflows/ci.yml)

`ssca` audits the dependencies and the CI configuration of npm, PyPI and Maven
projects in one run. It builds the full transitive dependency graph, writes
SBOMs, matches vulnerabilities, verifies hashes and Sigstore provenance, looks
for signs of malicious packages, audits CI workflows, scores every component
and turns the result into a pass/fail decision against a policy. Every run can
be repeated offline from a frozen data snapshot.

It is a research prototype developed for the master's thesis *A Study of
Security and Transparency Issues in Software Supply Chains*. How to repeat the
experiments of the thesis offline is described in [REPRODUCE.md](REPRODUCE.md);
a live demo of the CI gate is
[supply-chain-audit-demo](https://github.com/Vlad-Mirzoian/supply-chain-audit-demo).

## Features

| Module | What it does |
|---|---|
| Dependency graph (M0) | Full transitive graph from lockfiles or manifests, with the scope of every component (runtime, optional, provided, extra, development, test); detects lockfiles that are out of sync with their manifests |
| SBOM (M1) | CycloneDX 1.6 and SPDX 2.3 with the CISA minimum elements; scores SBOMs of other tools; SBOM diff |
| Vulnerabilities (M2) | OSV.dev advisories re-checked locally, aliases merged, CVSS, EPSS and CISA KEV; OpenVEX / CycloneDX VEX; optional package-level reachability |
| Integrity and provenance (M3) | Lockfile hashes compared with the registry, unexpected package sources and repositories, npm provenance and PEP 740 attestations verified with Sigstore, trusted SLSA builders |
| Package risk (M4) | Malicious-package indicators (publisher change, new install script, provenance regression, young new dependency, dependency confusion, …), typosquatting, a composite risk score with bands |
| CI audit (M5) | GitHub Actions and GitLab CI: unpinned actions and images, privileged triggers with untrusted checkout or artifacts, token permissions, script injection, `curl \| sh` |
| Policy and reports (M6) | YAML policy with type-checked rules, exceptions with expiry and non-removable baseline rules; JSON, SARIF, Markdown and HTML reports and an evidence manifest |

**Supported inputs**

- **npm:** package-lock.json (v1–v3), yarn.lock (v1 and berry), pnpm-lock.yaml, workspaces
- **PyPI:** uv.lock, poetry.lock, Pipfile.lock, requirements files, pyproject.toml
- **Maven:** pom.xml with parents, BOM imports and multi-module projects

## Installation

Requires Go 1.27 or later.

    go install github.com/Vlad-Mirzoian/supply-chain-audit/cmd/ssca@latest

or from a clone of the repository:

    go build -o ssca ./cmd/ssca

Prebuilt binaries for Linux, macOS and Windows are attached to the
[releases](https://github.com/Vlad-Mirzoian/supply-chain-audit/releases),
together with `SHA256SUMS` and SBOMs (SPDX, CycloneDX). Every binary has a
SLSA build provenance and an SBOM attestation signed with Sigstore; verify a
download with the GitHub CLI:

    sha256sum -c SHA256SUMS --ignore-missing
    gh attestation verify ssca_1.0.7_linux_amd64 --repo Vlad-Mirzoian/supply-chain-audit

## Quick start

Audit a project (the directory with its lockfile) and write the reports to
`ssca-out/`:

    ssca scan --out ssca-out path/to/project

```
## ❌ ssca supply-chain audit: FAIL

Project `pkg:pypi/pygoat@0.0.0` (pypi), 45 components (32 direct, max depth 3), scanned in 2.0 s.
Policy: built-in default policy (the project has no .ssca/policy.yaml).

| Band | Components |
|---|---|
| critical | 8 |
| high | 6 |
| medium | 15 |
| low | 16 |

### Policy violations (build blocked)

| Rule | Component | Finding | Message |
|---|---|---|---|
| band-critical | `pkg:pypi/django@4.2` |  | CRS 100.0 (critical) |
| critical-reachable-cve | `pkg:pypi/django@4.2` | GHSA-frmv-pr5f-9mcr | Django vulnerable to SQL injection … |
…
```

Other commands:

    ssca graph --tree --depth 2 .          # dependency graph and tree
    ssca sbom --out sbom/ .                # CycloneDX and SPDX SBOMs
    ssca sbom --validate other-tool.cdx.json
    ssca diff --mode release-vs-release old.cdx.json new.cdx.json
    ssca typosquat loadsh crossenv         # -> lodash, cross-env
    ssca ci-audit .                        # workflows and local actions

## Commands

| Command | Purpose |
|---|---|
| `scan [dir]` | full audit with policy decision (M0–M6) |
| `graph [dir]` | dependency graph summary, `--tree`, `--json` |
| `sbom [dir]` | write SBOMs with suppliers, licenses and hashes from the registries (`--no-enrich`: lockfile data only, no network); `--validate FILE` scores an SBOM against the CISA minimum elements |
| `diff A B` | compare two SBOMs; `release-vs-release` rates a newly added package with less than 7 days of release history as high |
| `typosquat NAME…` | check package names against popular packages, confirmed with the release history as in `scan` (`--names-only`: dictionary only, offline) |
| `ci-audit [dir]` | audit CI workflows and local actions (`--json`, `--sarif`) |
| `verify-artifact FILE` | verify a file against a Sigstore bundle |
| `cache` / `cache seal` | inspect or freeze the data snapshot |
| `version` | print the version (also `--version`) |

Main `scan` flags: `--out`, `--policy`, `--vex`, `--offline`, `--now`,
`--include-dev`, `--runtime-only`, `--reachability`. Every command prints its
flags with `-h`; all details are in [docs/USAGE.md](docs/USAGE.md).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | passed |
| 1 | policy violation: the build is blocked |
| 2 | analysis incomplete (data missing, lockfile out of sync, PyPI without a lockfile under `unpinned_dependencies: fail`, …): not reported as a pass unless the policy sets `incomplete_analysis: warn` |
| 3 | usage error: bad or misplaced flag (flags go before the directory), wrong directory, invalid policy or VEX document |
| 4 | self-check failure: a sealed data snapshot was modified |

## Policy

Without `--policy`, `scan` uses `.ssca/policy.yaml` of the project if it exists
and the built-in policy otherwise. A policy that keeps the built-in rules and
adds what is specific to the project:

```yaml
extends: builtin          # the built-in rules and thresholds apply
disable: [cooldown]       # ... except these
internal:
  scopes: ["@acme"]
  registry: https://npm.acme.internal/
thresholds:
  unpinned_dependencies: fail   # PyPI without a lockfile: incomplete analysis
```

Without `extends` the file replaces the built-in policy and lists every rule
that applies:

```yaml
thresholds:
  fail_on_band: critical
  warn_on_band: high
internal:
  scopes: ["@acme"]
  registry: https://npm.acme.internal/
rules:
  - id: critical-cve
    when: vuln.severity == 'critical' and component.production and not vuln.suppressed
    action: fail
  - id: cooldown
    when: component.release_age_days < 7
    action: warn
exceptions:
  - component: pkg:npm/lodash
    rule: critical-cve
    reason: 'accepted until upgrade (SEC-1)'
    expires: 2027-06-30
vex:
  - vex/not-affected.openvex.json
```

Rules are type-checked when the policy is loaded, so a misspelt field is an
error and not a rule that never fires. Three baseline rules (known-malicious
package, integrity failure, exploited vulnerability in runtime code) always
apply and cannot be removed by a policy file. See
[docs/USAGE.md#policy](docs/USAGE.md#policy).

## Use in CI

Ready templates for GitHub Actions and GitLab CI are in [docs/ci](docs/ci).
They pin every action and image, verify the ssca binary against its checksum,
keep the data snapshot in the CI cache and upload the SARIF report to code
scanning; `ssca ci-audit` finds nothing in them.

## Offline and reproducible runs

All responses of the data sources (OSV.dev, deps.dev, the registries, EPSS,
KEV, the Sigstore trusted root) are cached in `$SSCA_CACHE` (default
`~/.cache/ssca`). With `--offline` a scan uses only this snapshot, and with
`--now` it fixes the evaluation time, so the same snapshot gives the same
findings, scores and decision. `ssca cache seal` freezes a snapshot with a
SHA-256 manifest; a changed file then stops an offline run with exit code 4.

## Limitations

- Ecosystems: npm, PyPI and Maven only.
- Reachability is package-level (import statements), not function-level.
- The malicious-package signals and typosquatting rely on registry metadata
  and deps.dev; they flag suspicious releases for review and are not a proof
  of malice.
- Online runs depend on public services (OSV.dev, deps.dev, the registries).
  When one of them cannot be reached the result is incomplete (exit code 2),
  not a pass.
- It is a research prototype: interfaces and report formats may change.

## Development

    go test ./...

Tests run offline: data sources are replaced by local test servers, and inside
a test binary the network client refuses any non-loopback host.

## License

MIT, see [LICENSE](LICENSE).
