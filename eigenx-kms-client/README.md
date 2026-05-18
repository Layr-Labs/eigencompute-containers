# eigenx-kms-client

A CLI client for interacting with the EigenX distributed KMS operator network. Provides two subcommands:

- **`encrypt`** -- Encrypt data using Identity-Based Encryption (IBE) by fetching the master public key from the on-chain operator set.
- **`decrypt`** -- Retrieve and decrypt environment variables inside a TEE using GCP Confidential Space attestation and threshold key recovery from KMS operators.

## Building

```bash
# Build locally
make build

# Static linux binary
make build/static

# Docker
docker build -f Dockerfile .
```

The compiled binary is output to `bin/eigenx-kms-client`.

## Usage

```
eigenx-kms-client [global options] command [command options]
```

### Global Flags

These flags are shared by both subcommands and configure blockchain connectivity.

| Flag | Required | Default | Env Var | Description |
|------|----------|---------|---------|-------------|
| `--eth-rpc-url` | Yes | | `ETH_RPC_URL` | Ethereum RPC URL |
| `--avs-address` | Yes | | `AVS_ADDRESS` | AVS contract address for operator discovery |
| `--operator-set-id` | No | `0` | `OPERATOR_SET_ID` | Operator set ID for threshold decryption |
| `--log-level` | No | `info` | `LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) |

### `encrypt`

Encrypt a string using IBE. Discovers operators on-chain, fetches the master public key from the operator set, and encrypts the provided data. Outputs hex-encoded ciphertext.

```bash
eigenx-kms-client \
  --eth-rpc-url https://sepolia.infura.io/v3/KEY \
  --avs-address 0xABC... \
  --operator-set-id 1 \
  encrypt \
    --app-id 0xDEF... \
    --data '{"API_KEY":"secret123"}'
```

#### Flags

| Flag | Required | Default | Env Var | Description |
|------|----------|---------|---------|-------------|
| `--app-id` | Yes | | `APP_ID` | Application ID for IBE encryption |
| `--data` | Yes | | | Plaintext string to encrypt |
| `--output` | No | _(stdout)_ | | File path to write hex-encoded ciphertext |

#### Output

When `--output` is omitted, prints the hex-encoded ciphertext to stdout. When `--output` is provided, writes the ciphertext to the specified file.

### `decrypt`

Full TEE decryption workflow. Intended to run inside a GCP Confidential Space VM. Performs:

1. Generate ephemeral RSA key pair for secure transport
2. Obtain GCP Confidential Space attestation JWT
3. Verify attestation and extract image digest
4. Connect to Ethereum and discover KMS operators
5. Retrieve threshold-encrypted secrets from operators (using attestation for auth)
6. Verify secrets result integrity against KMS signing key
7. Decrypt environment variables using the recovered IBE private key
8. Derive EVM/Solana addresses from mnemonic and post to user API
9. Output environment variables

```bash
eigenx-kms-client \
  --eth-rpc-url https://sepolia.infura.io/v3/KEY \
  --avs-address 0xABC... \
  --operator-set-id 1 \
  decrypt \
    --app-id 0xDEF... \
    --kms-signing-key-file /etc/kms/key.pem \
    --userapi-url https://api.eigenx.com \
    --output /run/env
```

#### Flags

| Flag | Required | Default | Env Var | Description |
|------|----------|---------|---------|-------------|
| `--app-id` | Yes | | `APP_ID` | Application ID for IBE decryption |
| `--kms-signing-key-file` | Yes | `kms-signing-public-key.pem` | `KMS_SIGNING_KEY_FILE` | Path to KMS signing public key PEM file |
| `--userapi-url` | Yes | | `USERAPI_URL` | User API URL to POST attestation JWT |
| `--output` | No | _(stdout)_ | | File path to write `export KEY="VALUE"` lines |
| `--app-controller-address` | No | | `APP_CONTROLLER_ADDRESS` | AppController contract address |

#### Output

When `--output` is omitted, prints decrypted environment variables as pretty-printed JSON to stdout. When `--output` is provided, writes `export KEY="VALUE"` lines to the specified file (suitable for `source`-ing in a shell).

#### Environment Variables

The decrypt command also reads:

| Variable | Default | Description |
|----------|---------|-------------|
| `GCP_PROJECT_ID` | `eigenx-compute` | GCP project ID for attestation verification |

## Testing

```bash
make test
```

## Linting

```bash
make lint
```
