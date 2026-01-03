# vTLS Chrome Extension (v1) — Developer Guide

This document is the “contract” for a Chrome (MV3) extension that provides a MetaMask-like UX for vTLS:

- Show which Eigen apps are running / being used (per origin activity feed)
- Show whether responses are **vTLS encrypted** and/or **enclave-authenticated**
- Let the user **connect**, **verify**, and **send encrypted messages** via a `window.vtls` provider API

This extension is a **client** of `vtls-agent` (running inside the instance/enclave).

## Goals

- **Wallet-style UX**: per-origin connect/permissions + clear verification status
- **Works with existing apps**: observe traffic for status without requiring app changes
- **Reliable sending path**: use `window.vtls` to perform protected requests without CORS/body interception pitfalls

## Non-goals (v1)

- Proving the browser’s TLS session terminates inside the enclave (vTLS is an app-layer security layer on top of HTTPS)
- Automatically wrapping *all* website traffic into vTLS (too many edge cases: streaming, redirects, uploads, assets)

## Terminology

- **Origin**: `scheme://host` (e.g. `https://app.example.com`)
- **Protected surface**: a standardized route prefix that is vTLS-only (recommended: `/private/*`)
- **Bundle**: `GET /.well-known/vtls/v1/bundle` containing pubkeys + signature
- **Verified app**: bundle verified against the app’s KMS-signed identity

## Standardized server routing contract

### Bundle endpoint (always plaintext JSON)

- `GET /.well-known/vtls/v1/bundle`

### Protected surface (recommended)

Standardize on a single prefix:

- **Protected surface**: `/private/*`

Server-side expectation (recommended):

- Caddy routes `/.well-known/vtls/*` and `/private/*` to `vtls-agent`
- `vtls-agent` runs in `vtls_prefix` mode with `VTLS_PREFIX=/private`
- Requests to `/private/<x>` are decrypted and forwarded upstream as `/<x>`

The extension should treat `/private/*` as the “vTLS universe” for status + UX.

## What “vTLS status” means (the UI model)

The extension should avoid ambiguous claims. Use three nested states:

- **Plain HTTPS**: non-`/private/*` traffic (not vTLS)
- **vTLS surface**: `/private/*` response includes `X-VTLS: 1` (optional marker) or route matches the prefix
- **vTLS verified**: response has `X-VTLS-Signature` and the extension verifies it against the origin’s verified bundle `sig_pubkey`

Recommended user-facing badges:

- “Not protected” (plain HTTPS)
- “Encrypted” (vTLS surface)
- “Encrypted + Verified” (signature verified)

Important: only show “Verified” when you have actually verified the signature against a verified bundle for that origin.

## Extension architecture (Chrome MV3)

### Components

- **Service worker (background)**: cryptography, bundle caching, verification, request sending, event log
- **Content script**: injects provider into pages, bridges `postMessage` <-> `chrome.runtime.sendMessage`
- **In-page provider**: `window.vtls` API (dapp-style)
- **UI**: popup (and/or side panel) showing current origin status + activity + approvals

### Permissions (typical)

- `storage`: persist connections and bundle cache metadata
- `activeTab` / `tabs`: current site UX
- `host_permissions`: domains you want to observe and/or fetch
- `webRequest` + `webRequestBlocking` (or `declarativeNetRequest`) for observing headers (if you choose global monitoring)

Note: MV3 can observe headers well; request/response *bodies* are not consistently available for arbitrary page requests. This is why sending should go through the background (provider) for v1.

## Provider API (MetaMask-like)

## Do we need “Connect”?

Not strictly for **observing and verifying** vTLS traffic.

- If the extension is only **watching** `/private/*` and showing status (“encrypted”, “verified”), you can do that **without a connect step**, because verification is based on public data:
  - bundle fetch + verification
  - `X-VTLS-Signature` verification

However, a connect/permission step is still strongly recommended for a MetaMask-like UX when a website wants the extension to **act on the user’s behalf**, because otherwise any site can:

- trigger popups/prompts repeatedly (spam)
- attempt phishing flows that look like legitimate “send encrypted message” actions
- request the extension to decrypt and return plaintext to the page

### Recommended split (v1)

- **Observer mode (no connect required)**:
  - extension monitors `/private/*` (and/or `X-VTLS: 1`)
  - extension verifies `X-VTLS-Signature` when possible
  - UI shows per-origin activity + verification status

- **Provider mode (connect required)**:
  - site calls `window.vtls.*` to send encrypted requests or receive decrypted plaintext
  - extension requires explicit user approval per origin (and optional per-route allowlist)

This gives “no friction” for passive verification, but keeps user consent and phishing resistance for active actions.

### Connection / permissions

Expose a single entrypoint similar to `eth_requestAccounts`:

- `vtls_requestPermissions() → { origin, permissions }`
  - Prompts the user to “connect” the site to the extension.
  - **Always prompt on first use per origin**, even if the extension has already verified the origin’s bundle in observer mode.
  - Stores an allowlist per origin (e.g. allow protected requests to `/private/*`).

### Status

- `vtls_getStatus() → { origin, connected, verified, appAddress, bundleExpiresAt, lastBundleHash }`

### Protected fetch (recommended primary API)

- `vtls_fetch(input, init) → { status, headers, body }`
  - Behaves like `fetch`, but if the target path is under `/private/*`, the extension:
    - Ensures the origin is connected (calls must be user-approved on first use)
    - Ensures bundle is fresh (refetch/verify if needed)
    - Encrypts the request payload into a vTLS envelope
    - Sends the request from the background (avoids CORS issues for the page)
    - Verifies `X-VTLS-Signature`, decrypts response envelope
    - Returns plaintext to the page (or optionally returns ciphertext + verification data if requested)
  - **User approval policy (v1)**: require a user confirmation prompt for each protected request by default, unless the user has enabled “Always allow for this origin + prefix”.

Optional: provide `vtls_encrypt()` / `vtls_decrypt()` only for advanced apps. For a wallet UX, keep it to `vtls_fetch`.

## Cryptography contract (v1)

The extension must implement the same logic as the server:

### Bundle verification (high level)

1. Fetch bundle from `/.well-known/vtls/v1/bundle`
2. Verify `bundle_sig` using the expected app identity (KMS-signed material)
3. Cache:
   - `enc_pubkey`, `sig_pubkey`, `app_address`, `issued_at`, `expires_at`
   - `bundle_hash` (sha256 of canonical signing bytes)

### Request encryption

Given:

- bundle `enc_pubkey`
- generated client ephemeral X25519 keypair
- `bundle_hash` (32 bytes)

Derive:

- `shared = X25519(client_eph_priv, enc_pubkey)`
- `k = HKDF-SHA256(shared, salt=bundle_hash, info="vtls/1")` → 32 bytes

Encrypt:

- AES-256-GCM with random 12-byte `nonce`
- **Request AAD** must bind:
  - `bundle_hash`, `request_id`, `method`, `path`

Produce JSON envelope `VtlsEnvelopeV1`:

- `version: "vtls/1"`
- `bundle_hash` (base64)
- `request_id` (base64; recommended 16 random bytes)
- `client_ephemeral_pubkey` (base64; 32 bytes)
- `nonce` (base64; 12 bytes)
- `ciphertext` (base64)

### Response verification + decryption

For `/private/*` responses:

1. Require `X-VTLS-Signature`
2. Verify signature using `sig_pubkey` from the verified bundle over:
   - `sha256(ciphertext) || status || method || path || bundle_hash || request_id`
3. Decrypt response envelope using derived `k` and **Response AAD** binding:
   - `bundle_hash`, `request_id`, `status`, `method`, `path`

## Observing requests (global status dashboard)

If you want “show status for everything”:

- Filter to “Eigen apps” by:
  - domain allowlist/pattern, and/or
  - successfully fetching `/.well-known/vtls/v1/bundle` for the origin
- Then filter to vTLS surface:
  - path starts with `/private/` (recommended), and optionally
  - response has `X-VTLS: 1`

To label as “Verified”, the extension must:

- have a verified bundle cached for that origin, and
- see `X-VTLS-Signature` and verify it

Note: you won’t reliably decrypt arbitrary page responses from observation alone (body access limitations). Decryption should be shown for requests initiated via `vtls_fetch` (background-controlled).

## UX flows (recommended)

### Connect

1. Site calls `vtls_requestPermissions()`
2. Extension shows prompt:
   - origin
   - requested capabilities (send `/private/*` requests, read verification status)
3. **Always shown on first provider use per origin**, regardless of whether the origin is already “verified” from observer mode
4. User approves/denies

### Verify (automatic)

On first protected use, or on connect:

1. Fetch bundle
2. Verify against KMS-signed identity
3. Display:
   - `app_address`
   - verification result
   - bundle expiry timer

### Send (per-request confirmation)

For protected requests (e.g. anything under `/private/*`), prompt by default:

- origin + path
- decoded request preview (if JSON)
- “Verified” indicator (bundle verified + keys match)

Allow an opt-in “always allow for this origin + prefix” setting for power users (disables per-request prompts for that origin/prefix).

## Error handling (user-facing)

Keep errors explicit and actionable:

- **Bundle expired**: refetch bundle and retry
- **bundle_hash mismatch**: refresh bundle; warn about origin mismatch
- **Signature missing/invalid**: show “Not verified” and block if policy requires
- **Decrypt failed**: show tampering/mismatch warning; don’t pass plaintext to the page

`vtls-agent` returns JSON errors with `{ "error": { "code": "...", "message": "..." } }` for failures.

## Security notes

- Keep ephemeral private keys and derived symmetric keys **in the service worker**, not the page.
- Never expose `MNEMONIC`-derived server secrets (you never should have them client-side).
- Treat “Verified” as a strict state: it requires successful local cryptographic verification.



