# Supply-Chain Pinning

BreachScope pins executable CI dependencies to immutable identities.

## GitHub Actions

Every external action used by workflows is pinned to a full 40-character
commit SHA. The human-readable release version remains beside the pin as a YAML
comment.

Pinned release lines:

- `actions/checkout` — v4.4.0
- `actions/setup-python` — v5.6.0
- `actions/upload-artifact` — v4.6.2
- `docker/setup-buildx-action` — v3.12.0
- `docker/build-push-action` — v6.19.2
- `softprops/action-gh-release` — v2.6.2

`scripts/verify_supply_chain_pins.py --strict` rejects mutable action refs.

## Docker base image

The runtime base is pinned as both a readable tag and an immutable OCI index
digest:

`python:3.11.16-slim-bookworm@sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91`

The tag documents intent; the digest controls the actual bytes selected.

## Update maintenance

`.github/dependabot.yml` monitors both `github-actions` and `docker` weekly.
Dependency-update PRs should update the immutable SHA/digest together with the
human-readable version comment and pass the normal test/quality gates.

## Remaining supply-chain risk

P1-06 intentionally does **not** claim bit-for-bit reproducible OS package
installation. `apt-get` in Ubuntu CI runners and the Debian-based runtime still
uses distribution repositories without package-version or snapshot pinning.

That residual risk is recorded rather than hidden. Adding Debian/Ubuntu
snapshot repositories is a separate change because it affects repository
availability, security-update cadence, and runner/base-image compatibility.

The health-check `curl` occurrences found by the recon are local API probes,
documentation examples, or detection/test strings; they are not unverified
third-party binary downloads.
