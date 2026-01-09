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

#### mainnet-prod

| Tag | Client | Image URL | Digest | Git commit | Provenance signature |
| --- | ------ | --------- | ------ | ---------- | -------------------- |
| `tls-client-v0.2.2` | `tls-client` | `docker.io/eigenlayer/eigencloud-containers:37b11a303174f75486158e637ba59fecb53f0ce1-1767917654` | `sha256:54fc848e03fbf3fd549694d5ad6c2652e62cc8d1fb90f1399dd0f589491d181d` | `37b11a303174f75486158e637ba59fecb53f0ce1` | `MEUCIBUAGD/qtt1tSLvnroG3dp7x/i25Q8V0dDcdkd45oEfLAiEAlt2no3rmDL0G9pVsh8QtIgrxXTdtVRHh8UrN67ysf00=` |
| `kms-client-v0.2.2` | `kms-client` | `docker.io/eigenlayer/eigencloud-containers:37b11a303174f75486158e637ba59fecb53f0ce1-1767917481` | `sha256:d02017034331378097c61259d6dc385041d1ce12d6d677e0f836ee35ed65de8c` | `37b11a303174f75486158e637ba59fecb53f0ce1` | `MEYCIQDUNPDGKzM8nn7KCJF0u76VhzeKsQho514HFMl8kU/xqwIhALiHZ8HElTh71drfibPcOtGlK2yVyEfOtvO97C9Cna6f` |

#### sepolia-prod

| Tag | Client | Image URL | Digest | Git commit | Provenance signature |
| --- | ------ | --------- | ------ | ---------- | -------------------- |
| `tls-client-v0.2.2` | `tls-client` | `docker.io/eigenlayer/eigencloud-containers:37b11a303174f75486158e637ba59fecb53f0ce1-1767917655` | `sha256:736063771a43e909f8cdd165a156df7f47176e2004f4629cc972c3adda473e8e` | `37b11a303174f75486158e637ba59fecb53f0ce1` | `MEQCIDM1Df/tjDcak5BO6Zz5yVBAe2rtUrT8o2b44tpptQO7AiAoH1zTRRCtw3aa3Kr+J1C1nwTOLqw/URzvvCkYbGVUWQ==` |
| `kms-client-v0.2.2` | `kms-client` | `docker.io/eigenlayer/eigencloud-containers:37b11a303174f75486158e637ba59fecb53f0ce1-1767917483` | `sha256:4e986c0b074f6113e712ee9fbed80096af4f56b97469a7f16067d6bb91a264b9` | `37b11a303174f75486158e637ba59fecb53f0ce1` | `MEQCICeMBdS1d2W+3arxak/+y/q/R+d7Tpzy98uyWlRYaVgtAiBxGtHiLm0NQF839PZxTA+mg5bWAY0jA3p3aujrkeIZRg==` |
