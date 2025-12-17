# EigenCloud Containers

This repository holds the source for EigenCompute client binaries. These clients are built as dependency images and layered into EigenCompute workloads.

By default, EigenCompute TEE workloads layer in both the TLS client and the KMS client.

The point of publishing the source here is traceability: you can verify the exact git commit used to produce a given dependency image.

### Artifact convention

- Dependency binaries live at `/eigen/bin/*` in the dependency image.
- Consumers pin dependency images by digest and layer `/eigen/bin/*` into the final image at the same path.

### Distribution (Docker Hub)

- Registry: Docker Hub
- Org: `eigenlayer`
- Repo: `eigencloud-containers`
- Visibility: public
- Purpose: distribution / free egress
- Auth: Docker Hub Organization Access Token stored in Secret Manager

### Verifiable builds

- Release tags use the form `<client>-v*` (example: `tls-client-v1.2.3`).
- `/.github/workflows/verifiable-builds.yml` submits a build to the verifiable-build system (`POST /builds`).
- Per-client Dockerfile and build context live in `/.github/verifiable-builds/clients.json`.

### Published builds

After a tag build completes successfully, copy the build output (image URL, digest, git commit, provenance signature) into the table below.
This is a manual step and should be done as part of the release process.

| Tag | Client | Image URL | Digest | Git commit | Provenance signature |
| --- | ------ | --------- | ------ | ---------- | -------------------- |
| (example) `tls-client-v0.0.2` | `tls-client` | `…` | `sha256:…` | `…` | `…` |

### Clients in this repo

- `tls-client/` builds an image containing `/eigen/bin/tls-client`
- `kms-client/` builds an image containing `/eigen/bin/kms-client`
