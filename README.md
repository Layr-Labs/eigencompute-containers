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
| `tls-client-v0.2.1` | `tls-client` | `docker.io/eigenlayer/eigencloud-containers:fbf147169280aebb8f825b725f3eb8a9b6580e85-1767912620` | `sha256:c3cee3562c050c51fbfbbbbde34753353177689080b115ab6f746a5c6c2d9c63` | `fbf147169280aebb8f825b725f3eb8a9b6580e85` | `MEQCIGYnD6Vs2lgMvd8MqOonVm+r0F1jIVQDbrkHkwuErWR2AiBHyEP6mH76p+lZh6d8ZpGwX5XLAG0Q8LpAuCoYJ1uywA==` |
| `kms-client-v0.2.1` | `kms-client` | `docker.io/eigenlayer/eigencloud-containers:fbf147169280aebb8f825b725f3eb8a9b6580e85-1767912268` | `sha256:9f52576d030eaeca2522846059d9d64b2d584120e6bc9e80686584b989c39a6d` | `fbf147169280aebb8f825b725f3eb8a9b6580e85` | `MEUCICwlvi+R3tU6bKkEh/wiV6L4VcU/HF+IYIkF7v7cbiY8AiEAmck8/5aIF9x6fF1w1otR0MkBqiULhwaZ8Wa6JJChPF4=` |
