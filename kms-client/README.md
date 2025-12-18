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
  --userapi-url http://localhost:3000 \
  --log-level info
```

Write `export KEY="VALUE"` lines to a file:

```bash
go run ./cmd/kms-client \
  --kms-server-url http://localhost:8080 \
  --kms-signing-key-file ./kms-signing-public-key.pem \
  --output ./.env.exports
```

## KMS signing public keys

`kms-client` uses the KMS signing public key to **verify the server signature** on the response envelope before attempting to decrypt it.
This prevents a network attacker (or misconfigured endpoint) from feeding the client forged ciphertext.

Select the key that matches the network/environment you are targeting and pass it via `--kms-signing-key-file` (or `KMS_SIGNING_KEY_FILE`).

### Sepolia prod

```pem
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsk6ZdmmvBqFfKHs+1cYjIemRGN7h
1NatIEitFRyx+3q8wmTJ9LknTE1FwWBLcCNTseJDti8Rh+SaVxfGOyJuuA==
-----END PUBLIC KEY-----
```

### Mainnet-alpha prod

```pem
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfxbhXJjH4D0DH/iW5/rK1HzWS+f9
EyooZTrCYjCfezuOEmRuOWNaZLvwXN8SdzrvjWA7gSvOS85hLzp4grANRQ==
-----END PUBLIC KEY-----
```


