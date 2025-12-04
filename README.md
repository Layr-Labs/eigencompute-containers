# EigenCompute Containers

  Production container images for EigenCloud TEE compute infrastructure.

  ## Overview

  This repository hosts verified, production ready container images for the EigenCompute. All images are built using
   GCP cloud build process and published to GitHub Container Registry for transparency and auditability.

  ## Container Registry

  Images are available at:
  ghcr.io/layr-labs/eigencompute-containers

  ## Usage

  Pull an image:
  ```bash
  docker pull ghcr.io/layr-labs/eigencompute-containers/[IMAGE_NAME]:[TAG]
  ```

  All images in this repository are publicly readable and can be pulled without authentication.

### Environments

  This registry serves production environments:
  - Sepolia Prod: Production environment on Sepolia testnet
  - Mainnet Prod: Production environment on Ethereum mainnet

  Verification

  All container images are built using:
  - GCP Cloud Build
  - Public source code and build configurations