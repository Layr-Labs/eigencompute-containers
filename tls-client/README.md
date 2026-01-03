# tls-client

`tls-client` manages public TLS certificates for EigenCompute workloads. It deterministically derives keys from a mnemonic, obtains/renews certificates via ACME, and stores/fetches certificate chains via a certificate storage service.

In EigenCompute, this client is layered into TEE workloads by default.

## Artifact image (Dockerfile-only)

- `tls-client/Dockerfile` produces a minimal **dependency image** whose payload is **only** the binary at `/eigen/bin/tls-client`.
- The final stage is `FROM scratch`; CA certificates are layered in so the binary can make outbound TLS calls.

### Build the dependency image

From repo root:

- `docker build -f tls-client/Dockerfile tls-client`

### Extract the binary to your filesystem

Using BuildKit output (recommended):

- `docker buildx build -f tls-client/Dockerfile --output type=local,dest=./out tls-client`

This will write `./out/eigen/bin/tls-client`.

## Verifiable builds (on tag)

On new tags matching `<client>-v*` (example: `tls-client-v1.2.3`), the repo-root workflow `/.github/workflows/verifiable-builds.yml` submits a verifiable build. The workflow:

- Parses the client name from the tag prefix (everything before `-v`)
- Looks up `dockerfile_path` and `build_context_path` in `/.github/verifiable-builds/clients.json`

- `repo_url`: `https://github.com/<owner>/<repo>`
- `git_ref`: 40-char commit SHA that the tag points to
- `dockerfile_path`: `tls-client/Dockerfile`
- `build_context_path`: `tls-client`
- `dependencies`: optional list of image digests (provided as secret `VERIFIABLE_BUILD_DEPENDENCIES_JSON`, e.g. `["sha256:..."]`)

To add a new client (e.g. `kms-client`), create `kms-client/` with its `Dockerfile`, then add a new entry in `/.github/verifiable-builds/clients.json`.

## What it gives us

* **Deterministic keys**: same mnemonic (+ domain \[+ version]) → same ACME account key + TLS key.
* **Stateless TEE**: no local persistence; TLS key is derived in-enclave each boot.
* **Persistent storage**: cert chain (`fullchain.pem`) stored via API that validates GCE instance identity.
* **Survives upgrades**: certificates persist when instances are replaced during upgrades.
* **Caddy-ready**: writes `/run/tls/fullchain.pem` + `/run/tls/privkey.pem`.

## How it works

1. **Derive**

   * ACME account key: HKDF(seed, `"eigenx/acme-account/v1"`).
   * TLS key: HKDF(seed, `"eigenx/tls-key/v1"+domain[+version]`).
2. **Fetch or issue**

   * Call storage API: `GET /certs/<domain>`.
     API validates GCE instance identity token.
   * If valid → write `/run/tls/*`.
   * If missing/expiring → issue via ACME (HTTP-01 or TLS-ALPN-01), then `POST` new cert to storage API.
3. **Serve**

   * Caddy consumes `/run/tls/*` (no ACME in Caddy).

## Storage API contract

* **Auth**: requires GCE instance identity token (header: `X-Instance-Token`).
* **API endpoints**:

  * `GET /certs/<domain>` → fetch stored cert
  * `POST /certs/<domain>` → store new cert
* **Back-end storage**: certificates stored indexed by instance name and domain.

## Storage structure

```
certs/<instance_name>/<domain>/
  ├── cert.pem
  └── metadata.json
```

* `<instance_name>` = stable GCE instance name (e.g., `tee-0x123...`)
* Certificates persist across instance upgrades

## Boot sequence (per instance)

1. Derive TLS key from mnemonic.
2. Fetch GCE identity token from metadata server.
3. **GET** cert via storage API; if valid → write `/run/tls` → start app → start Caddy.
4. If missing/expiring: issue via ACME, `POST` cert to storage API → write `/run/tls`.
5. Optional renew loop: if cert < N days to expiry, re-issue and update via storage API.

## Caddy (external cert mode)

```caddy
{$DOMAIN} {
  tls /run/tls/fullchain.pem /run/tls/privkey.pem
  reverse_proxy 127.0.0.1:{$APP_PORT:3000}
}
:80 {
  redir https://{host}{uri} permanent
  handle /health { respond "OK" 200 }
}
```

## ACME notes

* Prefer **TLS-ALPN-01** (requires 443 free before Caddy starts).
  Use **HTTP-01** only if 80 is externally reachable / DNAT’d correctly.
* Using the **same derived account key** enables \~30-day **authorization reuse** (fewer challenges).
* Keep the ACME `certificate` URL if you want easy re-download (doesn’t count against issuance).

## Troubleshooting

* **Connection refused during ACME** → wrong port binding (e.g., external 80 → container 8080); bind solver to the effective container port or use TLS-ALPN-01.
* **Caddy "failed to start" but logs show server running** → your wrapper is grepping warnings; use `caddy validate` then `caddy run` (foreground) and check exit code.
* **Certificate not found after upgrade** → check storage API is accessible and GCE identity token is being fetched correctly.

## Security

* **Mnemonic** never leaves TEE; do not log/persist it.
* **TLS private key** never stored; only derived in TEE.
* Storage contains **public** certificates only (certificates are public by design).
* Storage API authenticates via GCE instance identity tokens.
* GCE tokens are separate from CC attestation tokens (used for KMS).
