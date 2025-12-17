# kms-client (eCloud KMS client)

`kms-client` fetches environment variables from an EigenCompute/ecloud KMS. It uses TEE attestation to authenticate, then verifies and decrypts the response.

In EigenCompute, this client is layered into TEE workloads by default.

Components:
- `cmd/kms-client`: CLI to fetch environment variables from the KMS server
- `pkg/envclient`: attestation token retrieval, request/response, signature verification, and decryption

## Artifact image (Dockerfile-only)

- `kms-client/Dockerfile` produces a minimal dependency image whose payload is the binary at `/eigen/bin/kms-client`.
- The final stage is `FROM scratch`. CA certificates are included so the binary can make outbound TLS calls.

## CLI usage

```bash
go run ./cmd/kms-client \
  --kms-server-url http://localhost:8080 \
  --kms-signing-key-file ./kms-signing-public-key.pem \
  --log-level info
```

Write `export KEY="VALUE"` lines to a file:

```bash
go run ./cmd/kms-client \
  --kms-server-url http://localhost:8080 \
  --kms-signing-key-file ./kms-signing-public-key.pem \
  --output ./.env.exports
```


