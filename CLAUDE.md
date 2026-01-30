# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains source code for EigenCompute client binaries that are built as dependency images and layered into EigenCompute TEE workloads. The repository provides verifiable, reproducible builds with full traceability from git commit to Docker image digest.

## Client Binaries

The repository contains three client binaries:

1. **tls-client** - Manages public TLS certificates for EigenCompute workloads using deterministic key derivation from mnemonics, ACME certificate provisioning, and remote certificate storage
2. **kms-client** - Fetches environment variables from the EigenCompute/ecloud KMS using TEE attestation for authentication
3. **eigenx-kms-client** - Built from the external eigenx-kms-go repository (not maintained in this repo)

## Build Commands

### Building Individual Clients

Each client can be built as a Docker image from the repo root:

```bash
# TLS client
docker build -f tls-client/Dockerfile tls-client

# KMS client
docker build -f kms-client/Dockerfile kms-client

# EigenX KMS client (builds from external repo)
docker build -f eigenx-kms-client/Dockerfile eigenx-kms-client
```

### Extracting Binaries

To extract the compiled binary to your local filesystem:

```bash
docker buildx build -f <client>/Dockerfile --output type=local,dest=./out <client>
```

This writes the binary to `./out/eigen/bin/<client-name>`.

### Testing

Run unit tests for a specific client:

```bash
cd <client-directory>
go test ./...
```

### Linting

Install and run golangci-lint:

```bash
cd <client-directory>
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8
golangci-lint run
```

## Architecture

### Artifact Convention

- All dependency binaries are placed at `/eigen/bin/*` in the dependency image
- Final stage uses `FROM scratch` with only CA certificates and the static binary
- Consumers pin dependency images by digest and layer `/eigen/bin/*` into workload images

### Verifiable Builds System

The repository uses a custom verifiable builds system to ensure reproducibility and traceability:

1. **Tagging**: Release tags follow the format `<client>-v*` (e.g., `tls-client-v1.2.3`)
2. **Workflow**: `.github/workflows/verifiable-builds.yml` triggers on tag push
3. **Configuration**: `.github/verifiable-builds/clients.json` maps each client to its Dockerfile and build context
4. **Process**:
   - Workflow parses client name from tag prefix (everything before `-v`)
   - Submits build request to verifiable-build API with repo URL, git ref, dockerfile path, and build context
   - Polls build status and outputs image URL, digest, git commit, and provenance signature
   - Provenance signature enables cryptographic verification of the build

### Distribution

- **Registry**: Docker Hub (`docker.io/eigenlayer/eigencloud-containers`)
- **Visibility**: Public
- **Authentication**: Uses Docker Hub Organization Access Token stored in GitHub Secrets

## Code Structure

### tls-client

- `cmd/tls-client/` - Main CLI entry point
- `cert/` - ACME certificate management using lego library
- `keys/` - Deterministic key derivation from mnemonics using HKDF
- `storage/` - Certificate storage interfaces (local and remote API)
- `config/` - Configuration management

Key concepts:
- Derives both ACME account key and TLS key deterministically from mnemonic
- TLS keys are never stored; derived in-enclave on each boot
- Certificates are stored remotely via API that validates GCE instance identity
- Writes certificates to `/run/tls/fullchain.pem` and `/run/tls/privkey.pem` for Caddy consumption

### kms-client

- `cmd/kms-client/` - Main CLI entry point
- `pkg/envclient/` - Core client logic for attestation token retrieval, request/response handling, signature verification, and decryption
- `pkg/crypto/` - Cryptographic operations including Solana key handling
- `pkg/types/` - Shared type definitions
- `internal/cli/` - CLI configuration and flag parsing

Key concepts:
- Uses TEE attestation tokens to authenticate with KMS server
- Verifies server signature on response envelope before decryption (prevents forged ciphertext)
- KMS signing public keys are environment-specific (Sepolia prod vs Mainnet-alpha prod)
- Can output environment variables as `export KEY="VALUE"` format to a file

### eigenx-kms-client

This client is built from an external repository (`github.com/Layr-Labs/eigenx-kms-go`) rather than maintained in this repo. The Dockerfile clones the external repo and builds the binary.

## CI/CD

### clients-ci.yml

Runs on push to master and all PRs:

- **client-test**: Runs `go test ./...` for tls-client and kms-client
- **client-lint**: Runs golangci-lint for tls-client and kms-client
- **client-docker-build**: Builds Docker images for all three clients

### verifiable-builds.yml

Triggered by release tags matching `*-v*` pattern. Submits build to verifiable-build system with EIP-712 signature-based authentication. Polls build status and outputs provenance information to GitHub Actions summary.

## Adding a New Client

1. Create a new directory with a Dockerfile
2. Add an entry to `.github/verifiable-builds/clients.json` with `dockerfile_path` and `build_context_path`
3. Add the client to the CI matrix in `.github/workflows/clients-ci.yml`
4. Tag with format `<client-name>-v<version>` to trigger verifiable build
