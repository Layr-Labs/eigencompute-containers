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
| `tls-client-v0.1.0` | `tls-client` | `docker.io/eigenlayer/eigencloud-containers:f066c21f574463047409aae0abd21765bc9c76a5-1766012751` | `sha256:98b3d848cec8d4c0feae011392e6e519a0af818e98bb4cae9ff0429bdf250cbd` | `f066c21f574463047409aae0abd21765bc9c76a5` | `MEUCIB5CxRDTVaPHKyHm1G5k5HmyD+O6G2vDP2RZGtlVuL67AiEArwJjYlg2MqELFv3YlIBkuO4jjfNKFqRt9M+qFkWPDeI=` |
| `kms-client-v0.1.0` | `kms-client` | `docker.io/eigenlayer/eigencloud-containers:f066c21f574463047409aae0abd21765bc9c76a5-1766012931` | `sha256:a49b592a9aa5838011cd1f5e5431109c039821b25951ea78c182baae632dd569` | `f066c21f574463047409aae0abd21765bc9c76a5` | `MEQCID1EMw2fuwk1oX8khcACbSG1Wqp0EmF9ik5j8oDOyhHZAiAfVMF8iot+u00ZKjrVFl8WRC7gkj7c8kXymTxYUnlCrg==` |

### Clients in this repo

- `tls-client/` builds an image containing `/eigen/bin/tls-client`
- `kms-client/` builds an image containing `/eigen/bin/kms-client`
