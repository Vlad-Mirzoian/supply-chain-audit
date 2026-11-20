# Reproducing the experiments of the thesis

The evaluation of ssca in the master's thesis *A Study of Security and Transparency Issues in Software Supply
Chains* (Section 4) is based on 83 stored ssca runs. Each of them can be repeated **offline** and gives the
same result as in the thesis, because every run reads its data (advisories, registry metadata, POMs, EPSS,
KEV, the Sigstore trusted root) only from a frozen *data snapshot*.

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

| Thesis result | Runs (`expected.json`) | Data of |
|---|---|---|
| RQ1 inventory and transitive coverage, comparison with Trivy, Grype, OSV-Scanner | `a/*` (16) | 20 Nov 2026 |
| RQ1 default mode, scan time (RQ6), calibration of the risk score | `a_default/*` (16) | 6–7 Nov 2026 |
| Hold-out corpus (a′) | `a2/*` (10) | 10–11 Nov 2026 |
| RQ2 precision and recall, Log4Shell cases | `b/*` (15) | 20 Nov 2026 |
| Pipfile.lock projects | `d/*` (2) | 10 Nov 2026 |
| RQ3 scope, reachability and VEX filtering | `reach/*` (12) | 6 Nov 2026 |
| RQ4 known malicious versions (runtime and development dependencies) | `c/*` (2), `c2/*` (1) | 20 Nov / 6 Nov 2026 |
| RQ4 fresh legitimate releases | `fresh/*` (2) | 10 Nov 2026 |
| RQ6 NFR-01: two projects of about 5 000 components | `nfr01/*` (2) | 11 Nov 2026 |
| Case study (CI/CD pipeline, Section 4.5) | `casestudy/*` (5) | 6 Nov 2026 |

The case study is also published as a live demo:
[supply-chain-audit-demo](https://github.com/Vlad-Mirzoian/supply-chain-audit-demo), where every attack
scenario is a pull request that ssca blocks.

Compared are the decision and exit code, the number of components and findings, the vulnerability findings per
severity, the violated rules, the reasons of an incomplete analysis and the data snapshot ID (except for the two
NFR-01 runs, whose stored report is the first of three cold runs while the archived snapshot is the cache left by
the last one; the note in `expected.json` says so). The stored runs were
made with ssca 1.0.0; release 1.0.2 gives the same results on all 83 runs (`replay.py`, 20 November 2026).

## Steps

**1. ssca.** Use a [release](https://github.com/Vlad-Mirzoian/supply-chain-audit/releases) (verify it as described
in the README) or build it: `go build -o ssca ./cmd/ssca`.

**2. Inputs.** Python 3.9 or later and git:

    python3 reproduce/fetch_corpus.py --dest work --sources

`--sources` also checks out the full source trees of the seven projects of the reachability runs. Every file is
checked against the SHA-256 in `corpus.json`.

**3. Data snapshots.** The snapshots are not in the repository (about 1.2 GB together) because they hold registry
metadata of third-party packages, including the names and e-mail addresses of their maintainers. They are
**available on request**: open an issue in this repository. Their SHA-256, which `replay.py` checks, are:

| Archive | Size | SHA-256 |
|---|---|---|
| ssca-snapshot-2026-11-20.tar.gz | 170 MB | `73524e534654b56aa7f1d68210570c6f46a9b371f70253a90faeed6d8c8f6cac` |
| ssca-snapshot-2026-11-06.tar.gz | 221 MB | `ece87fb8b4c23c344d4bf55b26c7eae45f2d969fc1cf59ecd770b2b11d7cd827` |
| ssca-snapshot-2026-11-07.tar.gz | 223 MB | `ef2ad989076f557162a70fb5f19604aa9d112cabdd13e2d325c7feecd1fb49de` |
| ssca-snapshot-holdout-2026-11-10.tar.gz | 132 MB | `47acec550329e94c6dc0fc65f719796075574460cb43ec6b9683bc17cd7fbe3a` |
| ssca-snapshot-holdout-2026-11-11.tar.gz | 132 MB | `10baddcb7403e545a922b5c5f8d79cab50c58be7da400fb041b998222797eef4` |
| ssca-snapshot-holdout-mem0-2026-11-11.tar.gz | 132 MB | `646ce4b3aef420c4fa3f0f3a97360cc7248738ac4f43527fee081c457eb80f13` |
| ssca-snapshot-corpus-d-2026-11-10.tar.gz | 35 MB | `7aa0a0c745e1778236158a14995f376d520ba216212f2994d5694769857ba354` |
| ssca-snapshot-fresh-2026-11-10.tar.gz | 66 MB | `298f845eceef57bd3e96b29dbd95f08d611ffbad73b06b9086af863371043730` |
| ssca-snapshot-nfr01-joplin-2026-11-11.tar.gz | 37 MB | `ee540eb09cdd9c5401f336fae4633a9bf5a9a80ccc5ad067f69358d14e9887d4` |
| ssca-snapshot-nfr01-novu-2026-11-11.tar.gz | 47 MB | `c0255a4852939d5233d3f01ba58b1c0abe9a850837f91b4e6b0ffd72b13358ef` |

The snapshot of 20 November 2026 is also sealed (`ssca cache seal`, seal
`sha256:9d68e7002e8bfba52929659f7f85c930`): an offline run on it stops with exit code 4 if any file was changed.

**4. Replay.** Put the archives into one directory and run:

    python3 reproduce/replay.py --ssca ./ssca --snapshots snapshots/ --work work/

Each run prints `same` or the fields that differ; `--only a/` restricts the replay to some runs. A single run can
also be repeated by hand with the command, working directory and snapshot given in `expected.json`, for example:

    SSCA_CACHE=snapshots/ssca-snapshot-2026-11-20 ssca scan --offline --now=<time> --out out corpus/a/NodeGoat
    python3 reproduce/check.py a/NodeGoat out/report.json

## Other tools and analysis

The comparison runs of 20 November 2026 used Trivy 0.76.1, Grype 0.121.0 with Syft 1.55.0 and OSV-Scanner 2.7.0
with their default options and pinned databases: the Trivy database of 2026-11-20 (UpdatedAt 18:59:53 UTC), the
Grype database v6.1.10 built 2026-11-20 (archive checksum
`sha256:6866d1685025e6001d422fb4be59f26feebacb151b3ff77b012d999e12b9af24`), and the OSV exports of npm, PyPI and
Maven of the same day, which OSV-Scanner read with `--offline-vulnerabilities`. The ground truth was taken from the
package managers of the projects (`mvn dependency:list`, `pip install --dry-run --report` with
`--uploaded-prior-to 2026-11-20T21:59:00Z`, `npm ls`, `uv export`, Poetry, pnpm, yarn) and, for the advisories, from
the OSV.dev query API on 20 November 2026. These databases, the raw outputs of the other tools, the ground truth and
the analysis scripts that compute the tables of Section 4 are available on request as well.

Not reproducible offline from the published material:

- OSV-Scanner resolves manifests without a lockfile (`pom.xml`, `requirements.txt`) through the online service
  deps.dev, so its inventory of such projects can change over time.
- The zero-day scenarios of RQ4 need a mock registry that serves the constructed package metadata; it is not
  published.
- Scan times depend on the machine (measured on 8 virtual cores and 8 GB of memory).
- The typosquatting evaluation (RQ5) uses a labelled data set of 23 134 package names that is not part of this
  repository.
