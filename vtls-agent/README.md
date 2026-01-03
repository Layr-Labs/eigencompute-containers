# vtls-agent

`vtls-agent` is a local reverse proxy intended to run **inside** an EigenCompute instance/enclave. It enables **proxy-safe application-layer E2EE** for selected HTTP routes without requiring any application code changes.

## Goals

- **Zero app changes**: your app continues to speak plain HTTP on localhost.
- **E2EE for selected routes**: browser encrypts → `vtls-agent` decrypts in-enclave → forwards plaintext to app → encrypts + signs response.
- **Stable verification bundle**: exposes `/.well-known/vtls/v1/bundle` for browser verification.

## Endpoints

### Bundle

- `GET /.well-known/vtls/v1/bundle`

Returns `VtlsBundleV1`:

- `version`: `"vtls/1"`
- `app_address`: EVM address derived from deterministic signing key
- `domain`: canonical domain the bundle is intended for
- `origin`: requesting origin (derived from `X-Forwarded-Proto` + host)
- `enc_pubkey`: base64 X25519 public key (32 bytes)
- `sig_pubkey`: base64 secp256k1 compressed public key (33 bytes)
- `issued_at`, `expires_at`: unix seconds
- `bundle_sig`: base64 compact secp256k1 signature over the canonical bundle fields

### Protected proxy

For protected requests, the inbound body is a `VtlsEnvelopeV1` JSON envelope:

- `version`: `"vtls/1"`
- `bundle_hash`: base64 sha256(bundle canonical bytes)
- `request_id`: base64 random bytes (recommended 16 bytes)
- `client_ephemeral_pubkey`: base64 X25519 ephemeral pubkey (32 bytes)
- `nonce`: base64 12 bytes (AES-GCM)
- `ciphertext`: base64 bytes

The response is also a `VtlsEnvelopeV1` envelope (same `bundle_hash`/`request_id`/`client_ephemeral_pubkey`, fresh `nonce` + new `ciphertext`) plus:

- `X-VTLS-Signature: <base64>` (compact secp256k1 signature)
- `X-VTLS-Bundle-Hash: <base64>`
- `X-VTLS-Request-Id: <base64>`
- `X-VTLS: 1` (optional marker header; useful for extensions/observers to classify traffic)

## Cryptography (v1)

- **Key derivation** (from `MNEMONIC` via BIP-39 seed + HKDF-SHA256):
  - X25519 encryption keypair: info = `"eigenx/vtls-enc/v1"`
  - secp256k1 signing keypair: info = `"eigenx/vtls-sig/v1"`
- **Shared secret**: `X25519(enc_priv, client_ephemeral_pubkey)`
- **Symmetric key**: `HKDF-SHA256(shared, salt=bundle_hash, info="vtls/1")` → 32 bytes
- **Request AEAD AAD binds**: `bundle_hash`, `request_id`, `method`, `path`
- **Response AEAD AAD binds**: `bundle_hash`, `request_id`, `status`, `method`, `path`
- **Response signature digest binds**: `sha256(ciphertext)`, `status`, `method`, `path`, `bundle_hash`, `request_id`

## Configuration (env)

- **`MNEMONIC`** (required): BIP-39 mnemonic phrase.
- **`APP_UPSTREAM`** (required): e.g. `http://127.0.0.1:3000`
- **`VTLS_LISTEN_ADDR`**: default `127.0.0.1:8181`
- **`VTLS_DOMAIN`**: optional override for bundle `domain` (otherwise derived from `Host`)
- **`VTLS_BUNDLE_TTL_SECS`**: default `300`
- **`VTLS_MODE`**:
  - `off`: passthrough only
  - `bundle_only`: only serves bundle, passthrough otherwise (default)
  - `protect_prefixes`: protect `VTLS_PROTECT_PREFIXES` (and also `VTLS_PREFIX` if present)
  - `vtls_prefix`: protect only `VTLS_PREFIX` (default `/vtls`) and strip it when proxying upstream
  - `all`: protect all routes (not recommended for initial rollout)
- **`VTLS_PROTECT_PREFIXES`**: comma-separated list like `/api/private,/rpc`
- **`VTLS_PREFIX`**: default `/vtls`

## Caddy integration (minimal)

Example pattern with a dedicated encrypted surface at `/private/*` (recommended: a single standardized prefix for all vTLS traffic):

```caddy
{$DOMAIN} {
  tls /run/tls/fullchain.pem /run/tls/privkey.pem

  # vTLS bundle + vTLS encrypted surface
  handle /.well-known/vtls/* {
    reverse_proxy 127.0.0.1:8181
  }
  handle /private/* {
    reverse_proxy 127.0.0.1:8181
  }

  # Everything else stays plaintext to the app
  handle {
    reverse_proxy 127.0.0.1:{$APP_PORT:3000}
  }
}
```

When using this pattern, set:

- `VTLS_MODE=vtls_prefix`
- `VTLS_PREFIX=/private`

## Notes / limitations (v1)

- This does **not** prove the browser’s TLS session terminates inside the enclave. vTLS is designed as an **application-layer E2EE + response authenticity layer on top of HTTPS**, so its guarantees still hold even if HTTPS terminates at a proxy: the proxy cannot decrypt protected payloads or forge enclave-authenticated responses.
- `bundle_hash` is stable for the bundle TTL (cached per `(domain, origin)`).
- Protected requests currently forward a minimal set of headers to the upstream app.

## Extension-friendly filtering (recommended)

If you standardize your protected surface to a single prefix (e.g. `/private/*`), extensions can “listen” with low noise by filtering on:

- **Route prefix**: path starts with `/private/`
- **Marker header**: `X-VTLS: 1` on responses (and optionally on requests if you choose to add it client-side)
- **Strong verification**: `X-VTLS-Signature` verifies against the origin’s verified bundle `sig_pubkey`


