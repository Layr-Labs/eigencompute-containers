# Plan: Update eigenx-kms-client to Use Distributed KMS from eigenx-kms-go

## Overview

Update `eigenx-kms-client` to use the `pkg/clients/kmsClient.Client` from `eigenx-kms-go` for distributed threshold cryptography. The client will maintain the same CLI interface as the old `kms-client` (single command that outputs environment variables) but leverage the new distributed KMS implementation using IBE (Identity-Based Encryption) and threshold signatures.

## Current State

### Already Implemented in eigenx-kms-client
Looking at the current code, eigenx-kms-client already has:
- ✅ `pkg/envManager` - Manages on-chain env retrieval from AppController contract
- ✅ `pkg/contractCaller` - Wraps AppController contract calls
- ✅ `pkg/clients/ethereumClient` - Basic Ethereum client wrapper
- ✅ `pkg/envclient` - OLD GCP attestation provider (to be replaced)
- ✅ `pkg/crypto`, `pkg/logger`, `pkg/types` - Supporting packages
- ✅ Partial main.go setup with ethereumClient, contractCaller, envManager

### Current Issues
1. **main.go line 74**: Still calls old `envclient.NewEnvClient` with `cfg.ServerURL` (which doesn't exist in config)
2. **main.go line 59**: AppControllerAddress is TODO (empty address)
3. **Missing integration**: Doesn't use `kmsClient.Client` from eigenx-kms-go
4. **config.go**: Missing AVSAddress and other blockchain flags

## Architecture

The refactored eigenx-kms-go provides a clean `kmsClient.Client` API with these key methods:

### kmsClient.Client API
```go
// Setup
client, err := kmsClient.NewClient(&kmsClient.ClientConfig{
    AVSAddress:     "0x...",
    OperatorSetID:  0,
    Logger:         zapLogger,
    ContractCaller: contractCaller,
})

// Get operators from blockchain
operators, err := client.GetOperators()

// Retrieve secrets with attestation (returns encrypted env + app private key)
result, err := client.RetrieveSecretsWithOptions(appID, &kmsClient.SecretsOptions{
    AttestationMethod: "gcp",  // or "intel" or "ecdsa"
    ImageDigest:       "sha256:...",
    RSAPrivateKeyPEM:  rsaPrivKeyPEM,
    RSAPublicKeyPEM:   rsaPubKeyPEM,
})

// Result contains:
// - result.AppPrivateKey (recovered from threshold signatures)
// - result.EncryptedEnv (encrypted environment from operators)
// - result.PublicEnv (public environment from operators)
```

### Two Approaches for Env Retrieval

**Approach A: Operators provide env (via `/secrets` endpoint)** ✅ CHOSEN
- Client calls `kmsClient.RetrieveSecretsWithOptions`
- Operators return `EncryptedEnv + EncryptedPartialSig`
- Client decrypts partial sigs, recovers private key
- Client decrypts env using recovered key

**Approach B: On-chain env registry (via `envManager`)** (Optional)
- Client calls `envManager.GetEnvironmentForLatestRelease` to get encrypted env from AppController contract
- Client calls `kmsClient.RetrieveSecretsWithOptions` to get app private key
- Client decrypts env using `envManager.DecryptSecretEnv`

---

## Milestone 1: Configuration & Dependencies (~30 min)

**Goal**: Update configuration to support distributed KMS parameters and verify dependencies are in place.

### Tasks

- [ ] Add CLI flag `AVSAddressFlag` to `eigenx-kms-client/internal/cli/flags.go`
- [ ] Add CLI flag `OperatorSetIDFlag` to `eigenx-kms-client/internal/cli/flags.go`
- [ ] Add CLI flag `AppIDRequiredFlag` to `eigenx-kms-client/internal/cli/flags.go`
- [ ] Add CLI flag `AppControllerAddressFlag` to `eigenx-kms-client/internal/cli/flags.go` (optional)
- [ ] Update `Config` struct in `eigenx-kms-client/internal/cli/config.go` with new fields
- [ ] Update `NewConfigFromCLI` in `eigenx-kms-client/internal/cli/config.go` to read new flags
- [ ] Add `NewLogger` function to `eigenx-kms-client/internal/cli/config.go`
- [ ] Run `go mod tidy` to verify dependencies
- [ ] Verify build succeeds: `cd eigenx-kms-client && go build ./cmd/kms-client`

### Task 1.1: Add Required CLI Flags

**File**: `eigenx-kms-client/internal/cli/flags.go`
**Action**: Add blockchain-specific flags after line 44:

```go
	AVSAddressFlag = &cli.StringFlag{
		Name:     "avs-address",
		Usage:    "AVS contract address for operator discovery",
		Required: true,
		EnvVars:  []string{"AVS_ADDRESS"},
	}

	OperatorSetIDFlag = &cli.UintFlag{
		Name:    "operator-set-id",
		Usage:   "Operator set ID to use for threshold decryption",
		Value:   0,
		EnvVars: []string{"OPERATOR_SET_ID"},
	}

	AppIDRequiredFlag = &cli.StringFlag{
		Name:     "app-id",
		Usage:    "Application ID for IBE decryption (required)",
		Required: true,
		EnvVars:  []string{"APP_ID"},
	}

	AppControllerAddressFlag = &cli.StringFlag{
		Name:    "app-controller-address",
		Usage:   "AppController contract address (optional, for on-chain env retrieval)",
		EnvVars: []string{"APP_CONTROLLER_ADDRESS"},
	}
```

### Task 1.2: Update config.go

**File**: `eigenx-kms-client/internal/cli/config.go`

Replace entire file with:

```go
package cli

import (
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

type Config struct {
	ETHRpcURL              string
	AVSAddress             string
	OperatorSetID          uint32
	AppID                  string
	AppControllerAddress   string
	KMSSigningKey          string
	OutputFile             string
	UserAPIURL             string
	Debug                  bool
}

func NewConfigFromCLI(c *cli.Context) *Config {
	return &Config{
		ETHRpcURL:            c.String(ETHRpcURLFlag.Name),
		AVSAddress:           c.String(AVSAddressFlag.Name),
		OperatorSetID:        uint32(c.Uint(OperatorSetIDFlag.Name)),
		AppID:                c.String(AppIDRequiredFlag.Name),
		AppControllerAddress: c.String(AppControllerAddressFlag.Name),
		KMSSigningKey:        c.String(KMSSigningKeyFileFlag.Name),
		OutputFile:           c.String(OutputFileFlag.Name),
		UserAPIURL:           c.String(UserAPIURLFlag.Name),
		Debug:                c.Bool(Debug.Name),
	}
}

func NewLogger(debug bool) (*zap.Logger, error) {
	if debug {
		return zap.NewDevelopment()
	}
	return zap.NewProduction()
}
```

### Task 1.3: Verify Dependencies

**File**: `eigenx-kms-client/go.mod`

Verify these dependencies are present:
- `github.com/Layr-Labs/chain-indexer` - For Ethereum client
- `github.com/Layr-Labs/eigenx-kms-go` - For kmsClient, crypto, attestation
- `github.com/Layr-Labs/eigenx-contracts` - For AppController bindings

**Verification**: `cd eigenx-kms-client && go mod tidy && go build ./cmd/kms-client` should succeed.

---

## Milestone 2: Main Integration with kmsClient.Client (~1 hour)

**Goal**: Rewrite main.go to use distributed KMS instead of centralized server.

### Tasks

- [ ] Update imports in `eigenx-kms-client/cmd/kms-client/main.go`
- [ ] Update CLI flags in main app definition
- [ ] Implement `generateRSAKeyPair()` helper function
- [ ] Implement `deriveAddresses()` helper function
- [ ] Implement `calculateAddressNonce()` helper function
- [ ] Implement `postJWTToUserAPI()` helper function
- [ ] Rewrite `runClient()` function with 10-step flow
- [ ] Test build: `go build ./cmd/kms-client`

### Task 2.1: Update imports

**File**: `eigenx-kms-client/cmd/kms-client/main.go`

Replace imports (lines 3-19) with:

```go
import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	kmscli "github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/internal/cli"
	localcrypto "github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/crypto"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/envclient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/ethereum/go-ethereum/common"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)
```

### Task 2.2: Update CLI flags

**File**: `eigenx-kms-client/cmd/kms-client/main.go`

Update Flags slice (around line 25):

```go
		Flags: []cli.Flag{
			kmscli.ETHRpcURLFlag,
			kmscli.AVSAddressFlag,
			kmscli.OperatorSetIDFlag,
			kmscli.AppIDRequiredFlag,
			kmscli.AppControllerAddressFlag,
			kmscli.Debug,
			kmscli.KMSSigningKeyFileFlag,  // May be unused with new system
			kmscli.OutputFileFlag,
			kmscli.UserAPIURLFlag,
		},
```

### Task 2.3: Implement Helper Functions

Add these helper functions after `writeEnvFile`:

```go
// postJWTToUserAPI posts an attestation JWT to the user API
func postJWTToUserAPI(ctx context.Context, logger *zap.Logger, userAPIURL string, jwt string) error {
	payload := map[string]string{"jwt": jwt}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JWT payload: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", userAPIURL+"/attestation", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	logger.Sugar().Info("Successfully posted JWT to user API")
	return nil
}

// generateRSAKeyPair generates an RSA key pair for encrypting partial signatures in transit
func generateRSAKeyPair() ([]byte, []byte, error) {
	// Use eigenx-kms-go/pkg/encryption for RSA key generation
	rsaEncryption := encryption.NewRSAEncryption()
	privKeyPEM, pubKeyPEM, err := rsaEncryption.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}
	return privKeyPEM, pubKeyPEM, nil
}

// deriveAddresses derives EVM and Solana addresses from a mnemonic
func deriveAddresses(mnemonic string, count int) ([]string, []string, error) {
	return localcrypto.DeriveAddressesFromMnemonic(mnemonic, count)
}

// calculateAddressNonce creates a nonce from derived addresses for attestation
func calculateAddressNonce(evmAddrs, solanaAddrs []string) string {
	addresses := map[string]interface{}{
		"evm_addresses":    evmAddrs,
		"solana_addresses": solanaAddrs,
	}
	addressBytes, _ := json.Marshal(addresses)
	digest := localcrypto.CalculateSignableDigest(localcrypto.AppDerivedAddressesHeader, addressBytes)
	return hex.EncodeToString(digest)
}
```

### Task 2.4: Rewrite runClient Function

**File**: `eigenx-kms-client/cmd/kms-client/main.go`

Replace runClient function with the following 10-step flow:

```go
func runClient(c *cli.Context) error {
	ctx := context.Background()
	cfg := kmscli.NewConfigFromCLI(c)

	// Create logger
	l, err := kmscli.NewLogger(cfg.Debug)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	// Step 1: Generate ephemeral RSA key pair for encrypting partial signatures
	l.Sugar().Info("Generating RSA key pair for secure transport")
	rsaPrivKeyPEM, rsaPubKeyPEM, err := generateRSAKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Step 2: Generate GCP attestation JWT with nonce
	l.Sugar().Info("Requesting GCP Confidential Space attestation")
	tokenProvider := envclient.NewConfidentialSpaceTokenProvider(l)

	// Use app ID as nonce (simple and deterministic)
	gcpJWT, err := tokenProvider.GetToken(ctx, "EigenX KMS", cfg.AppID)
	if err != nil {
		return fmt.Errorf("failed to get GCP attestation: %w", err)
	}

	// Step 3: Parse JWT to extract image digest automatically
	l.Sugar().Info("Parsing attestation claims from GCP JWT")

	// Note: We need GCP project ID - either from env var or config
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		projectID = "eigenx-compute" // Default
		l.Sugar().Warn("GCP_PROJECT_ID not set, using default", "project_id", projectID)
	}

	verifier, err := attestation.NewAttestationVerifier(ctx, l.Sugar(), projectID, 15*time.Minute, cfg.Debug)
	if err != nil {
		return fmt.Errorf("failed to create attestation verifier: %w", err)
	}

	claims, err := verifier.VerifyAttestation(ctx, gcpJWT, attestation.GoogleConfidentialSpace)
	if err != nil {
		return fmt.Errorf("failed to verify attestation: %w", err)
	}

	l.Sugar().Infow("Extracted attestation claims",
		"app_id", claims.AppID,
		"image_digest", claims.ImageDigest)

	// Step 4: Create Ethereum client and contract caller
	l.Sugar().Infow("Connecting to Ethereum", "rpc", cfg.ETHRpcURL)
	ethClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   cfg.ETHRpcURL,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	l1Client, err := ethClient.GetEthereumContractCaller()
	if err != nil {
		return fmt.Errorf("failed to get Ethereum contract caller: %w", err)
	}

	contractCaller, err := caller.NewContractCaller(l1Client, nil, l)
	if err != nil {
		return fmt.Errorf("failed to create contract caller: %w", err)
	}

	// Step 5: Create KMS client
	l.Sugar().Infow("Creating KMS client", "avs", cfg.AVSAddress, "operator_set_id", cfg.OperatorSetID)
	kmsClientInstance, err := kmsClient.NewClient(&kmsClient.ClientConfig{
		AVSAddress:     cfg.AVSAddress,
		OperatorSetID:  cfg.OperatorSetID,
		Logger:         l,
		ContractCaller: contractCaller,
	})
	if err != nil {
		return fmt.Errorf("failed to create KMS client: %w", err)
	}

	// Step 6: Retrieve secrets using distributed KMS with GCP attestation
	l.Sugar().Info("Retrieving secrets from distributed KMS operators")
	result, err := kmsClientInstance.RetrieveSecretsWithOptions(cfg.AppID, &kmsClient.SecretsOptions{
		AttestationMethod: "gcp",
		ImageDigest:       claims.ImageDigest, // From parsed GCP JWT
		RSAPrivateKeyPEM:  rsaPrivKeyPEM,
		RSAPublicKeyPEM:   rsaPubKeyPEM,
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve secrets: %w", err)
	}

	l.Sugar().Infow("Retrieved secrets from operators",
		"responses", result.ResponseCount,
		"threshold", result.ThresholdNeeded)

	// Step 7: Decrypt environment data using recovered app private key
	l.Sugar().Info("Decrypting environment with recovered private key")

	// Parse encrypted env (should be hex-encoded IBE ciphertext)
	encryptedEnvBytes, err := hex.DecodeString(result.EncryptedEnv)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted env: %w", err)
	}

	decryptedEnvBytes, err := crypto.DecryptForApp(cfg.AppID, result.AppPrivateKey, encryptedEnvBytes)
	if err != nil {
		return fmt.Errorf("failed to decrypt environment: %w", err)
	}

	// Step 8: Parse environment JSON
	var envVars map[string]string
	if err := json.Unmarshal(decryptedEnvBytes, &envVars); err != nil {
		return fmt.Errorf("failed to unmarshal env JSON: %w", err)
	}

	// Merge public env if present
	if result.PublicEnv != "" {
		var publicEnv map[string]string
		if err := json.Unmarshal([]byte(result.PublicEnv), &publicEnv); err != nil {
			l.Sugar().Warnw("Failed to parse public env", "error", err)
		} else {
			for k, v := range publicEnv {
				if _, exists := envVars[k]; !exists {
					envVars[k] = v
				}
			}
		}
	}

	// Step 9: Derive addresses from mnemonic and post to user API
	if mnemonic, ok := envVars["MNEMONIC"]; ok && cfg.UserAPIURL != "" {
		l.Sugar().Info("Deriving addresses from mnemonic")

		evmAddrs, solanaAddrs, err := deriveAddresses(mnemonic, 5)
		if err != nil {
			l.Sugar().Warnw("Failed to derive addresses", "error", err)
		} else {
			// Create nonce from derived addresses
			addrNonce := calculateAddressNonce(evmAddrs, solanaAddrs)

			// Get attestation JWT with address nonce
			addressJWT, err := tokenProvider.GetToken(ctx, "EigenX Dashboard", addrNonce)
			if err != nil {
				l.Sugar().Warnw("Failed to get address attestation", "error", err)
			} else {
				if err := postJWTToUserAPI(ctx, l, cfg.UserAPIURL, addressJWT); err != nil {
					l.Sugar().Warnw("Failed to post addresses to user API", "error", err)
				} else {
					l.Sugar().Info("Posted derived addresses to user API")
				}
			}
		}
	}

	// Step 10: Post general attestation to user API (optional)
	if cfg.UserAPIURL != "" {
		l.Sugar().Info("Posting attestation to user API")
		userJWT, err := tokenProvider.GetToken(ctx, "EigenX Dashboard", cfg.AppID)
		if err != nil {
			l.Sugar().Warnw("Failed to get user API attestation", "error", err)
		} else {
			if err := postJWTToUserAPI(ctx, l, cfg.UserAPIURL, userJWT); err != nil {
				l.Sugar().Warnw("Failed to post to user API", "error", err)
			}
		}
	}

	// Step 11: Output environment variables
	envJSONBytes, _ := json.Marshal(envVars)

	if cfg.OutputFile != "" {
		return writeEnvFile(cfg, envJSONBytes)
	}

	pretty, _ := json.MarshalIndent(envVars, "", "  ")
	fmt.Printf("%s\n", string(pretty))
	return nil
}
```

---

## Milestone 3: Update Dockerfile (~15 min)

**Goal**: Update Dockerfile to build eigenx-kms-client locally (no git clone).

### Tasks

- [ ] Replace Dockerfile with local build configuration
- [ ] Test Docker build: `docker build -f eigenx-kms-client/Dockerfile eigenx-kms-client`
- [ ] Verify binary location: `/eigen/bin/eigenx-kms-client`
- [ ] Test Docker run: `docker run --rm eigenx-kms-client --help`

### Task 3.1: Update Dockerfile

**File**: `eigenx-kms-client/Dockerfile`

Replace entire file with:

```dockerfile
FROM golang:1.25 AS builder
WORKDIR /src

# Download modules and build the binary
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -extldflags '-static'" \
    -o /out/eigenx-kms-client \
    ./cmd/kms-client

FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/eigenx-kms-client /eigen/bin/eigenx-kms-client
ENTRYPOINT ["/eigen/bin/eigenx-kms-client"]
```

---

## Milestone 4: Testing & Validation (~30 min)

**Goal**: Verify the client works end-to-end with distributed KMS operators.

### Tasks

- [ ] Build test: `cd eigenx-kms-client && go build ./cmd/kms-client`
- [ ] Help test: `./kms-client --help` (verify new flags are present)
- [ ] Docker build test: `docker build -f eigenx-kms-client/Dockerfile eigenx-kms-client`
- [ ] Docker help test: `docker run --rm eigenx-kms-client --help`
- [ ] Integration test with operators (if available)
- [ ] Verify output format matches old kms-client

### Task 4.1: Build Test

```bash
cd eigenx-kms-client
go mod tidy
go build ./cmd/kms-client
./kms-client --help
```

**Expected**: Should display help with new flags:
- `--eth-rpc-url`
- `--avs-address` (required)
- `--operator-set-id`
- `--app-id` (required)
- `--debug`
- `--output-file`
- `--userapi-url`

### Task 4.2: Docker Build Test

```bash
docker build -f eigenx-kms-client/Dockerfile eigenx-kms-client
docker run --rm eigenx-kms-client --help
```

**Expected**: Docker build succeeds, binary is at `/eigen/bin/eigenx-kms-client`.

### Task 4.3: Integration Test (requires running operators)

```bash
./eigenx-kms-client \
  --eth-rpc-url http://localhost:8545 \
  --avs-address 0x1234567890123456789012345678901234567890 \
  --operator-set-id 0 \
  --app-id my-app-id \
  --userapi-url http://localhost:3000 \
  --debug
```

**Expected output flow**:
```
INFO  Generating RSA key pair for secure transport
INFO  Requesting GCP Confidential Space attestation
INFO  Parsing attestation claims from GCP JWT
INFO  Extracted attestation claims  app_id=my-app-id image_digest=sha256:abc123...
INFO  Connecting to Ethereum  rpc=http://localhost:8545
INFO  Creating KMS client  avs=0x1234... operator_set_id=0
INFO  Fetching operators from chain
INFO  Found operators on-chain  count=3
INFO  Retrieving secrets from distributed KMS operators
INFO  Collecting partial signatures  threshold=2 total_operators=3
INFO  Collected partial signature from operator  operator_index=1
INFO  Collected partial signature from operator  operator_index=2
INFO  Successfully collected threshold partial signatures  collected=2 threshold=2
INFO  Retrieved secrets from operators  responses=2 threshold=2
INFO  Decrypting environment with recovered private key
INFO  Successfully decrypted data
INFO  Deriving addresses from mnemonic
INFO  Posted derived addresses to user API
{
  "MNEMONIC": "word1 word2 ...",
  "API_KEY": "secret123",
  ...
}
```

---

## Implementation Summary

### What This Achieves
- ✅ Same CLI interface as old kms-client
- ✅ Distributed threshold cryptography (no single point of failure)
- ✅ GCP Confidential Space attestation (proves TEE execution)
- ✅ IBE encryption/decryption (Boneh-Franklin scheme)
- ✅ Operator-hosted encrypted env (via `/secrets` endpoint)
- ✅ Local build (no git clone in Dockerfile)
- ✅ Address derivation from mnemonic preserved
- ✅ User API JWT posting preserved

### Critical Files Modified

1. `eigenx-kms-client/internal/cli/flags.go` - Add AVS, operator-set-id, app-id flags
2. `eigenx-kms-client/internal/cli/config.go` - Update Config struct and add NewLogger
3. `eigenx-kms-client/cmd/kms-client/main.go` - Complete rewrite of runClient + add helpers
4. `eigenx-kms-client/Dockerfile` - Local build

### Key Integration Points

**RSA Key Generation**: Use `eigenx-kms-go/pkg/encryption.RSAEncryption.GenerateKeyPair()`

**Attestation JWT**: Use existing `envclient.ConfidentialSpaceTokenProvider`

**Image Digest**: Extract from GCP JWT using `attestation.VerifyAttestation`

**Address Derivation**: Use local `pkg/crypto.DeriveAddressesFromMnemonic`

**GCP Project ID**: Read from `GCP_PROJECT_ID` environment variable, default to `eigenx-compute`
