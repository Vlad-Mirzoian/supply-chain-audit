# Reproducing the experiments of the thesis

The evaluation of ssca in the master's thesis *A Study of Security and Transparency Issues in Software Supply
Chains* (Section 4) is based on 84 stored ssca runs. All data they use (advisories, registry metadata, POMs, EPSS,
KEV, the Sigstore trusted root) was collected on one day, 25 November 2026, into one *data snapshot*, which was
then sealed. Each run can be repeated **offline** on that snapshot and gives the same result as in the thesis.

This folder contains what is needed to repeat them:

| File | Content |
|---|---|
| [`reproduce/corpus.json`](reproduce/corpus.json) | the 49 input projects: GitHub repository and pinned commit, the files that were scanned, SHA-256 of every file |
| [`reproduce/fetch_corpus.py`](reproduce/fetch_corpus.py) | downloads the inputs at the pinned commits and checks their hashes |
| [`reproduce/inputs/`](reproduce/inputs) | constructed inputs that are not on GitHub (Log4Shell Maven cases, lockfiles with known malicious versions, fresh releases) |
| [`reproduce/vex/`](reproduce/vex) | the VEX documents used by the reachability runs |
| [`reproduce/expected.json`](reproduce/expected.json) | every run: command, working directory, data snapshot and the expected result |
| [`reproduce/replay.py`](reproduce/replay.py) | repeats the runs offline and compares them with `expected.json` |
| [`reproduce/check.py`](reproduce/check.py) | compares one `report.json` with its expected result |

## What is reproduced

| Thesis result | Runs (`expected.json`) |
|---|---|
| RQ1 inventory and transitive coverage, comparison with Trivy, Grype, OSV-Scanner; default mode, scan time (RQ6), calibration of the risk score | `a/*` (16) |
| RQ1 and RQ6 with `--runtime-only` | `a_runtime_only/*` (16) |
| Hold-out corpus (a′) | `a2/*` (10) |
| RQ2 precision and recall, Log4Shell cases | `b/*` (15) |
| Pipfile.lock projects | `d/*` (2) |
| RQ3 scope, reachability and VEX filtering | `reach/*` (12) |
| RQ4 known malicious versions (runtime and development dependencies) | `c/*` (2), `c2/*` (2) |
| RQ4 fresh legitimate releases (sample of 25 November 2026) | `fresh/*` (2) |
| RQ6 NFR-01: two projects of about 5 000 components | `nfr01/*` (2) |
| Case study (CI/CD pipeline, Section 4.5) | `casestudy/*` (5) |

All runs use `--now=2026-11-25T00:00:00Z`.

The case study is also published as a live demo:
[supply-chain-audit-demo](https://github.com/Vlad-Mirzoian/supply-chain-audit-demo), where every attack
scenario is a pull request that ssca blocks.

Compared are the decision and exit code, the number of components and findings, the vulnerability findings per
severity, the violated rules, the reasons of an incomplete analysis and the data snapshot ID. The stored results
are those of ssca 1.0.5, except the five case-study runs, which were repeated with ssca 1.0.6 after the policy of
the demo was reduced to its project-specific rules (26 November 2026, same snapshot and `--now`); ssca 1.0.6 and 1.0.7
reproduce all 84 runs.

## Steps

**1. ssca.** Use a [release](https://github.com/Vlad-Mirzoian/supply-chain-audit/releases) (verify it as described
in the README) or build it: `go build -o ssca ./cmd/ssca`.

**2. Inputs.** Python 3.9 or later and git:

    python3 reproduce/fetch_corpus.py --dest work --sources

`--sources` also checks out the full source trees of the seven projects of the reachability runs. Every file is
checked against the SHA-256 in `corpus.json`.

**3. Data snapshot.** The snapshot is not in the repository because it holds registry metadata of third-party
packages, including the names and e-mail addresses of their maintainers. It is **available on request**: open an
issue in this repository. Its SHA-256, which `replay.py` checks:

| Archive | Size | SHA-256 |
|---|---|---|
| ssca-snapshot-2026-11-25.tar.gz | 402 MB | `cb643ef42ed3ca03407ab7aa86060342a6243a1548ab2ff968aa1ac5f25978e9` |

The snapshot is sealed (`ssca cache seal`, seal `sha256:186cb252091b7c7047a4acb21ec9007e`): an offline run on it
stops with exit code 4 if any file was changed.

**4. Replay.** Put the archive into a directory and run:

    python3 reproduce/replay.py --ssca ./ssca --snapshots snapshots/ --work work/

Each run prints `same` or the fields that differ; `--only a/` restricts the replay to some runs. A single run can
also be repeated by hand with the command, working directory and snapshot given in `expected.json`, for example:

    SSCA_CACHE=snapshots/ssca-snapshot-2026-11-25 ssca scan --offline --now=2026-11-25T00:00:00Z --out out corpus/a/NodeGoat
    python3 reproduce/check.py a/NodeGoat out/report.json

## Other tools and analysis

The comparison runs of 25 November 2026 used Trivy 0.76.1, Grype 0.121.0 with Syft 1.55.0 and OSV-Scanner 2.7.0
with their default options and databases downloaded that day: the Trivy database UpdatedAt 2026-11-24 19:04:37 UTC,
the Grype database v6.1.10 built 2026-11-24 (archive checksum
`sha256:fdf0cdec0b112f6769c3fd38cd5f992a3bb6162a4ab2fe30d639d14ae41ea8a9`), and the OSV exports of npm and PyPI of
24 November and Maven of 23 November (the latest at the download), which OSV-Scanner read with
`--offline-vulnerabilities`. The ground truth was taken from the package managers of the projects
(`mvn dependency:list`, `pip install --dry-run --report` with `--uploaded-prior-to 2026-11-25T01:04:28Z`, `npm ls`,
`uv export`, Poetry, pnpm, yarn) and, for the advisories, from the OSV.dev query API on 25 November 2026. These databases, the raw outputs of the other tools, the ground truth and
the analysis scripts that compute the tables of Section 4 are available on request as well.

Not reproducible offline from the published material:

- OSV-Scanner resolves manifests without a lockfile (`pom.xml`, `requirements.txt`) through the online service
  deps.dev, so its inventory of such projects can change over time.
- The zero-day scenarios of RQ4 need a mock registry that serves the constructed package metadata; it is not
  published.
- Scan times depend on the machine (measured on 8 virtual cores and 8 GB of memory).
- The typosquatting evaluation (RQ5) uses a labelled data set of 23 134 package names that is not part of this
  repository.
