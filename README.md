# EigenCompute Containers - Dev

  Development and testing container images for EigenCLoud TEE compute infrastructure.

  ## Overview

  This repository hosts development container images for the EigenCompute platform. Images here are for **testing and
  development purposes only** and should not be used in production environments.

  ## Container Registry

  Images are available at:
  ghcr.io/layr-labs/eigencompute-containers-dev

  ## Usage

  Pull an image:
  ```bash
  docker pull ghcr.io/layr-labs/eigencompute-containers-dev/[IMAGE_NAME]:[TAG]
  ```

  All images in this repository are publicly readable and can be pulled without authentication.

  Environment

  This registry serves the development environment:
  - Sepolia Dev: Development and testing environment on Sepolia testnet

### Important Notice

  These images are for development and testing only.

  - Images may contain experimental features
  - Stability is not guaranteed
  - Images may be updated or removed without notice
  - Do not use in production environments

  For production images, see https://github.com/layr-labs/eigencompute-containers.

  Verification

  Development images follow the same build process as production:
  - Reproducible builds with Cloud Build
  - Public source code and build configurations