Test data copied from sigstore-go v1.3.0 (Apache-2.0), pkg/testing/data:
the npm provenance bundle of sigstore@2.0.0 (SLSA v1, built on a GitHub-hosted
runner) and the public-good trusted root it verifies against.

`acme-orders-api-1.4.0.tgz` and its bundle: a GitHub artifact attestation
(actions/attest-build-provenance, SLSA v1, build type
`https://actions.github.io/buildtypes/workflow/v1`) made on a GitHub-hosted
runner by the case-study workflow of supply-chain-audit-demo on 2026-11-20;
`trusted_root-2026-11-06.json` is the Sigstore public-good trusted root as
fetched through TUF on 2026-11-06, which it verifies against.
