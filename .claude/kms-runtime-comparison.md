# Runtime Comparison: kms-client vs eigenx-kms-client

## Architecture Overview

### kms-client (Old - Centralized KMS)
**Single point of trust**: Centralized KMS server owns master key and decrypts environment variables

### eigenx-kms-client (New - Distributed KMS)
**No single point of trust**: Distributed operators use threshold cryptography (t-of-n) and IBE encryption

---

## CLI Flags Comparison

### kms-client Flags
```bash
--kms-server-url value        # Single KMS server URL
--kms-signing-key-file value  # KMS signing public key PEM file
--app-id value                # App ID (debug only)
--log-level value             # Log level
--output value                # Output file path
--userapi-url value           # User API URL for attestation JWT
```

### eigenx-kms-client Flags
```bash
--eth-rpc-url value             # Ethereum RPC URL (NEW)
--avs-address value             # AVS contract address (NEW)
--operator-set-id value         # Operator set ID (NEW)
--app-id value                  # Application ID (REQUIRED, not debug only)
--app-controller-address value  # AppController contract address (NEW, optional)
--debug                         # Debug mode (NEW)
--kms-signing-key-file value    # KMS signing public key PEM file (REMOVED - no longer used)
--output value                  # Output file path
--userapi-url value             # User API URL for attestation JWT
```

**Key Changes**:
- ❌ Removed: `--kms-server-url` (no single server)
- ✅ Added: `--eth-rpc-url`, `--avs-address`, `--operator-set-id` (blockchain integration)
- ✅ Changed: `--app-id` is now **required** (not debug-only)
- ❌ Deprecated: `--kms-signing-key-file` (not used in new flow)

---

## Runtime Flow Comparison

### kms-client Flow (6 steps)

```
1. Generate ephemeral RSA key pair
   ├─ Private key: for decryption
   └─ Public key: for envelope encryption

2. Get GCP attestation JWT
   └─ Nonce: SHA256(RSA public key)

3. Send request to centralized KMS server
   ├─ Endpoint: POST {kms-server-url}/env/v2
   ├─ Payload: { jwt, rsaPublicKeyPEM }
   └─ Server: Decrypts with master key, re-encrypts with RSA public key

4. Verify KMS signature
   └─ Uses kms-signing-key-file to verify response signature

5. Decrypt response
   └─ RSA-OAEP + AES-256-GCM decryption

6. Output environment variables
   └─ JSON or export format
```

### eigenx-kms-client Flow (10 steps)

```
1. Generate ephemeral RSA key pair
   ├─ Private key: for partial signature transport
   └─ Public key: for operator responses

2. Get GCP attestation JWT
   └─ Nonce: SHA256(RSA public key)

3. Parse JWT claims
   ├─ Extract: app_id, image_digest
   └─ Verify: attestation validity

4. Connect to Ethereum
   └─ Create contract caller for on-chain queries

5. Create KMS client
   ├─ Query AVS contract for operator list
   └─ Discover: operator URLs, BLS public keys

6. Retrieve secrets from distributed operators
   ├─ Endpoint: POST {operator-url}/secrets (for each operator)
   ├─ Payload: { app_id, image_digest, rsaPublicKeyPEM, attestation }
   ├─ Response: Encrypted partial private key + encrypted env
   └─ Threshold: Collect t-of-n responses

7. Decrypt environment with recovered private key
   ├─ Combine partial keys using BLS threshold cryptography
   ├─ Recover full app private key
   └─ IBE decryption: ciphertext → plaintext env

8. Parse environment JSON
   └─ Merge public env (if available)

9. Derive addresses from mnemonic
   ├─ Generate: EVM addresses (0-9)
   ├─ Generate: Solana addresses (0-9)
   └─ POST to user API (if configured)

10. Output environment variables
    └─ JSON or export format
```

---

## Key Technical Differences

| Feature | kms-client | eigenx-kms-client |
|---------|-----------|-------------------|
| **Architecture** | Centralized server | Distributed operators (t-of-n) |
| **Encryption** | RSA-OAEP + AES-256-GCM | IBE (Boneh-Franklin, BLS12-381) |
| **Key Management** | Server holds master key | Threshold secret sharing |
| **Operator Discovery** | Hardcoded URL | On-chain AVS contract query |
| **Blockchain Integration** | None | Ethereum RPC required |
| **Attestation Verification** | Server-side only | Client-side + server-side |
| **Response Signature** | Ed25519 signature | BLS signature (threshold) |
| **Single Point of Failure** | Yes (KMS server) | No (t-of-n operators) |
| **Encrypted Env Storage** | Server storage | Operator storage (`/secrets` endpoint) |
| **Public Env** | Not supported | Supported (merged with encrypted) |

---

## API Endpoints

### kms-client
```
POST {kms-server-url}/env/v2

Request:
{
  "jwt_with_attested_rsa_key": "...",
  "rsa_key_pem": "..."
}

Response (Signed):
{
  "signature": "...",
  "data": {
    "encrypted_combined_env": "..."  // RSA-OAEP + AES-256-GCM
  }
}
```

### eigenx-kms-client
```
POST {operator-url}/secrets

Request:
{
  "app_id": "...",
  "image_digest": "sha256:...",
  "rsa_public_key_pem": "...",
  "attestation_jwt": "..."
}

Response (per operator):
{
  "encrypted_partial_key": "...",     // RSA-encrypted BLS key share
  "encrypted_env": "...",             // IBE-encrypted env (hex)
  "public_env": "...",                // Plaintext public env (JSON)
  "bls_signature": "...",             // Operator BLS signature
  "operator_index": 1
}

Note: Client collects t-of-n responses and combines them
```

---

## Cryptographic Primitives

### kms-client
- **Ephemeral encryption**: RSA-2048 OAEP
- **Symmetric encryption**: AES-256-GCM
- **Signature verification**: Ed25519
- **Key derivation**: HKDF-SHA256 (for address derivation)

### eigenx-kms-client
- **Ephemeral encryption**: RSA-2048 OAEP (for partial key transport)
- **IBE encryption**: Boneh-Franklin scheme, BLS12-381 curve
- **Threshold cryptography**: BLS signature aggregation (t-of-n)
- **Signature verification**: BLS multi-signature
- **Key derivation**: HKDF-SHA256 (for address derivation)

---

## Security Properties

### kms-client
- ✅ TEE attestation proves code integrity
- ✅ Ephemeral RSA keys (never stored)
- ✅ Signature verification prevents tampering
- ❌ **Single point of compromise** (KMS server)
- ❌ Server can decrypt all secrets

### eigenx-kms-client
- ✅ TEE attestation proves code integrity
- ✅ Ephemeral RSA keys (never stored)
- ✅ Signature verification prevents tampering
- ✅ **No single point of compromise** (t-of-n threshold)
- ✅ No single operator can decrypt secrets
- ✅ Byzantine fault tolerance (up to n-t malicious operators)

---

## Dependencies Comparison

### kms-client
```
- No blockchain dependencies
- No operator discovery logic
- Simple HTTP client
- Crypto: RSA, AES, Ed25519
```

### eigenx-kms-client
```
- Ethereum client (go-ethereum)
- AVS contract bindings
- Operator discovery + health checks
- BLS12-381 crypto library
- IBE crypto primitives
- Threshold cryptography
```

---

## Performance Characteristics

### kms-client
- **Latency**: ~200-500ms (single HTTP request)
- **Network calls**: 2 (attestation + KMS)
- **Bottleneck**: Single KMS server

### eigenx-kms-client
- **Latency**: ~1-3 seconds (multiple operators + blockchain query)
- **Network calls**: 1 (attestation) + 1 (ETH RPC) + n (operators)
- **Bottleneck**: Slowest t operators (need threshold responses)
- **Parallelization**: Operator requests made concurrently

---

## Output Format (Identical)

Both clients produce identical output:

**JSON output** (to stdout):
```json
{
  "API_KEY": "secret123",
  "DB_PASSWORD": "pass456"
}
```

**Export output** (to file):
```bash
export API_KEY="secret123"
export DB_PASSWORD="pass456"
```

---

## Migration Path

### What Stays the Same
- ✅ CLI output format (JSON/export)
- ✅ File permissions (0600)
- ✅ User API posting (attestation + addresses)
- ✅ Address derivation (mnemonic → EVM/Solana)
- ✅ GCP Confidential Space attestation

### What Changes
- ❌ Must provide Ethereum RPC URL
- ❌ Must specify AVS contract address
- ❌ Must specify operator set ID
- ❌ `--app-id` becomes required (not debug-only)
- ❌ No single KMS server URL
- ✅ Encrypted env now fetched from operators
- ✅ No `--kms-signing-key-file` needed

### Environment Setup
**Old**:
```bash
kms-client \
  --kms-server-url https://kms.example.com \
  --kms-signing-key-file /path/to/key.pem \
  --userapi-url https://api.example.com \
  --output /run/env
```

**New**:
```bash
eigenx-kms-client \
  --eth-rpc-url https://sepolia.infura.io/v3/YOUR_KEY \
  --avs-address 0x1234567890abcdef... \
  --operator-set-id 1 \
  --app-id my-app-123 \
  --userapi-url https://api.example.com \
  --output /run/env
```

---

## Summary

**kms-client** is a **simple, centralized** solution:
- Single KMS server owns master key
- Fast (single HTTP request)
- Simple deployment
- **Security risk**: Single point of compromise

**eigenx-kms-client** is a **distributed, trustless** solution:
- No single party can decrypt secrets
- Threshold cryptography (Byzantine fault tolerant)
- Blockchain-based operator discovery
- **Tradeoff**: More complex, slightly higher latency
- **Benefit**: Eliminates single point of failure

The new client is designed for **production workloads** where **eliminating single points of trust** is critical.
