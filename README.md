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

### Latest published builds


| Tag | Client | Image URL | Digest | Git commit | Provenance signature |
| --- | ------ | --------- | ------ | ---------- | -------------------- |
| `tls-client-v0.2.0` | `tls-client` | `docker.io/eigenlayer/eigencloud-containers:35b4a32126f4168b0a9f19da01af910984ac38de-1766134518` | `sha256:b216e7e520be80f8ddeec71ff7cf71d75bb083f58492b8d03443905756cc51a1` | `35b4a32126f4168b0a9f19da01af910984ac38de` | `MEUCIQCIpa5CKPJnL3E75AGQ/ORX/DXxpW/jFQiVQFJg6Xj+iwIgY2kP1Q8Npe7gDxsrVQ4179j5cqd3NZwA+IKPhMEmpwk=` |
| `kms-client-v0.2.0` | `kms-client` | `docker.io/eigenlayer/eigencloud-containers:35b4a32126f4168b0a9f19da01af910984ac38de-1766134337` | `sha256:2aa4baebf526aae74a780df29a8827ea12114b8279a359d06886d21ce707cd72` | `35b4a32126f4168b0a9f19da01af910984ac38de` | `MEQCIG8NOAz8w97nOf9LHYVfdxqfBFFQwCTr7GUM5Qm/wXhKAiAFVhtSggaHk5gy9bRGtSypGirhdrfM7JxyQt1LM+BaZw==` |
