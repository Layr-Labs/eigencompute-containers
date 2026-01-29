# Plan: Update eigenx-kms-client to Use Distributed KMS from eigenx-kms-go

## Overview

Update `eigenx-kms-client` to use the `pkg/clients/kmsClient.Client` from `eigenx-kms-go` for distributed threshold cryptography. The client will maintain the same CLI interface as the old `kms-client` (single command that outputs environment variables) but leverage the new distributed KMS implementation using IBE (Identity-Based Encryption) and threshold signatures.

## Milestones

### Milestone 1: Configuration & Dependencies (30 min)
- Add required CLI flags (avs-address, operator-set-id, app-id)
- Update Config struct to support new blockchain parameters
- Update go.mod dependencies
- Verify build succeeds

### Milestone 2: Main Integration (1 hour)
- Update main.go imports to use eigenx-kms-go packages
- Rewrite runClient function to use kmsClient.Client
- Integrate GCP attestation with distributed KMS flow
- Add helper functions for user API posting

### Milestone 3: Address Derivation & Output (30 min)
- Port address derivation logic from old kms-client
- Implement address nonce calculation and user API posting
- Ensure output formatting matches old kms-client behavior

### Milestone 4: Docker & Build (15 min)
- Update Dockerfile for local build
- Test Docker build
- Verify binary location and entrypoint

### Milestone 5: Testing & Validation (30 min)
- Build and run locally
- Verify integration with mock/test operators
- Validate output format matches old kms-client

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
1. **main.go line 79**: Still calls old `envclient.NewEnvClient` with `cfg.ServerURL` (which doesn't exist in config)
2. **main.go line 64**: AppControllerAddress is TODO (empty address)
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

**Approach A: Operators provide env (via `/secrets` endpoint)**
- Client calls `kmsClient.RetrieveSecretsWithOptions`
- Operators return `EncryptedEnv + EncryptedPartialSig`
- Client decrypts partial sigs, recovers private key
- Client decrypts env using recovered key

**Approach B: On-chain env registry (via `envManager`)**
- Client calls `envManager.GetEnvironmentForLatestRelease` to get encrypted env from AppController contract
- Client calls `kmsClient.RetrieveSecretsWithOptions` to get app private key
- Client decrypts env using `envManager.DecryptSecretEnv`

**Recommended: Approach A** (simpler, follows eigenx-kms-go pattern)

## Detailed Implementation Plan

### Milestone 1: Configuration & Dependencies

**Goal**: Update configuration to support distributed KMS parameters and verify dependencies are in place.

#### Task 1.1: Add Required CLI Flags

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

	ImageDigestFlag = &cli.StringFlag{
		Name:    "image-digest",
		Usage:   "Container image digest for attestation (e.g., sha256:abc123...)",
		EnvVars: []string{"IMAGE_DIGEST"},
	}

	AppControllerAddressFlag = &cli.StringFlag{
		Name:    "app-controller-address",
		Usage:   "AppController contract address (optional, for on-chain env retrieval)",
		EnvVars: []string{"APP_CONTROLLER_ADDRESS"},
	}
```

**Note**: We're removing `ImageDigestFlag` since image digest will be extracted from GCP JWT automatically.

#### Task 1.2: Update config.go
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

#### Task 1.3: Verify Dependencies

**File**: `eigenx-kms-client/go.mod`

**Action**: Run `go mod tidy` and verify these dependencies are present:
- `github.com/Layr-Labs/chain-indexer` - For Ethereum client
- `github.com/Layr-Labs/eigenx-kms-go` - For kmsClient, crypto, attestation
- `github.com/Layr-Labs/eigenx-contracts` - For AppController bindings (if using on-chain)

**Verification**: `cd eigenx-kms-client && go mod tidy && go build ./cmd/kms-client` should succeed.

---

### Milestone 2: Main Integration with kmsClient.Client

**Goal**: Rewrite main.go to use distributed KMS instead of centralized server.

#### Task 2.1: Update imports
**File**: `eigenx-kms-client/cmd/kms-client/main.go`

Replace imports (lines 3-19) with:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	kmscli "github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/internal/cli"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/envclient"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/envManager"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/urfave/cli/v2"
)
```

#### Task 2.2: Update CLI flags
**File**: `eigenx-kms-client/cmd/kms-client/main.go`

Update Flags slice (lines 25-32):

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

#### Task 2.3: Rewrite runClient function
**File**: `eigenx-kms-client/cmd/kms-client/main.go`

Replace runClient function (lines 42-93) with:

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

	// Check if eigenx-kms-go has this, otherwise use local crypto package
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
		projectID = "eigenx-compute" // Default or from config
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

		// Use local crypto package for address derivation
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

	// Step 10: Output environment variables
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

	envJSONBytes, _ := json.Marshal(envVars)

	if cfg.OutputFile != "" {
		return writeEnvFile(cfg, envJSONBytes)
	}

	pretty, _ := json.MarshalIndent(envVars, "", "  ")
	fmt.Printf("%s\n", string(pretty))
	return nil
}
```

#### Task 2.4: Add helper functions

Add after runClient:

```go
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

// Helper to generate RSA key pair (check if eigenx-kms-go/pkg/crypto has this)
func generateRSAKeyPair() ([]byte, []byte, error) {
	// If eigenx-kms-go/pkg/crypto has GenerateRSAKeyPairPEM, use it
	// Otherwise use local crypto package from eigenx-kms-client
	// For now, placeholder - will verify which one exists
	return nil, nil, fmt.Errorf("TODO: implement RSA key generation")
}

// Helper to derive addresses (use local crypto package)
func deriveAddresses(mnemonic string, count int) ([]string, []string, error) {
	// Use eigenx-kms-client/pkg/crypto/crypto.go and crypto/solana.go
	// These should already have DeriveAddressesFromMnemonic
	return nil, nil, fmt.Errorf("TODO: implement address derivation")
}

// Helper to calculate nonce from addresses
func calculateAddressNonce(evmAddrs, solanaAddrs []string) string {
	// Match old kms-client behavior for nonce calculation
	// Likely involves marshaling addresses to JSON and hashing
	return ""
}
```

---

### Milestone 3: Address Derivation & User API Integration

**Goal**: Port address derivation logic from old kms-client and integrate with user API.

#### Task 3.1: Implement Address Derivation Helpers

#### 3.1 Add eigenx-kms-go dependency
**File**: `eigenx-kms-client/go.mod`

The go.mod already references `eigenx-kms-go/kms-client` packages. Update to use the new structure:

```go
module github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client

go 1.25.0

require (
	github.com/Layr-Labs/chain-indexer v<latest>
	github.com/Layr-Labs/eigenx-kms-go v<latest>
	github.com/Layr-Labs/eigenx-contracts v<latest>  // For AppController bindings
	github.com/cenkalti/backoff/v5 v5.0.3
	github.com/ethereum/go-ethereum v1.16.7
	github.com/gagliardetto/solana-go v1.14.0
	github.com/lestrrat-go/jwx/v3 v3.0.12
	github.com/miguelmota/go-ethereum-hdwallet v0.1.3
	github.com/urfave/cli/v2 v2.27.7
	go.uber.org/zap v1.27.1
	golang.org/x/crypto v0.45.0
)
```

Run `go mod tidy` after changes.

**File**: `eigenx-kms-client/cmd/kms-client/main.go`

**Action**: Implement the helper functions added in Task 2.4:

1. **generateRSAKeyPair()**: Check if `eigenx-kms-go/pkg/crypto` or `eigenx-kms-go/pkg/encryption` has RSA key pair generation. If not, use the implementation from old `eigenx-kms-client/pkg/crypto/crypto.go`.

2. **deriveAddresses()**: Use the existing `eigenx-kms-client/pkg/crypto` package:
   ```go
   import localcrypto "github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/crypto"

   func deriveAddresses(mnemonic string, count int) ([]string, []string, error) {
       return localcrypto.DeriveAddressesFromMnemonic(mnemonic, count)
   }
   ```

3. **calculateAddressNonce()**: Match the old kms-client behavior by creating a digest of the addresses JSON.

#### Task 3.2: Verify Address Posting Flow

**Action**: Ensure the user API posting matches the old kms-client:
- POST to `{userAPIURL}/attestation`
- Payload: `{"jwt": "..."}`
- JWT contains addresses in nonce claim

---

### Milestone 4: Update Dockerfile

#### Task 4.1: Update Dockerfile for local build
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

**Verification**: `docker build -f eigenx-kms-client/Dockerfile eigenx-kms-client` should succeed.

---

### Milestone 5: Testing & Validation

**Goal**: Verify the client works end-to-end with distributed KMS operators.

#### Task 5.1: Build Test
```bash
cd eigenx-kms-client
go mod tidy
go build ./cmd/kms-client
./kms-client --help
```

**Expected**: Should display help with new flags (--eth-rpc-url, --avs-address, --operator-set-id, --app-id).

#### Task 5.2: Docker Build Test
```bash
docker build -f eigenx-kms-client/Dockerfile eigenx-kms-client
docker run --rm eigenx-kms-client --help
```

**Expected**: Docker build succeeds, binary is at `/eigen/bin/eigenx-kms-client`.

#### Task 5.3: Integration Test (requires running operators)
```bash
./eigenx-kms-client \
  --eth-rpc-url http://localhost:8545 \
  --avs-address 0x1234567890123456789012345678901234567890 \
  --operator-set-id 0 \
  --app-id my-app-id \
  --userapi-url http://localhost:3000 \
  --debug
```

**Expected output**:
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

## Alternative Approach: On-Chain Env Registry (Optional)

If you want to use on-chain env registry instead of operators providing env:

### Modified runClient (Step 4-5)

```go
	// Step 4a: Parse GCP JWT to get attestation claims
	verifier, err := attestation.NewAttestationVerifier(ctx, l.Sugar(), "project-id", 15*time.Minute, cfg.Debug)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	claims, err := verifier.VerifyAttestation(ctx, gcpJWT, attestation.GoogleConfidentialSpace)
	if err != nil {
		return fmt.Errorf("failed to verify attestation: %w", err)
	}

	// Step 4b: Get encrypted env from on-chain AppController
	if cfg.AppControllerAddress == "" {
		return fmt.Errorf("app-controller-address is required for on-chain env retrieval")
	}

	appCC, err := caller.NewContractCaller(l1Client, &caller.ContractsConfig{
		AppControllerAddress: common.HexToAddress(cfg.AppControllerAddress),
	}, l)
	if err != nil {
		return fmt.Errorf("failed to create app contract caller: %w", err)
	}

	envMgr, err := envManager.NewEnvManager(l, appCC)
	if err != nil {
		return fmt.Errorf("failed to create env manager: %w", err)
	}

	publicEnv, encryptedEnvJWE, err := envMgr.GetEnvironmentForLatestRelease(ctx, claims)
	if err != nil {
		return fmt.Errorf("failed to get environment from contract: %w", err)
	}

	// Step 5: Use kmsClient to get app private key only (not env)
	result, err := kmsClientInstance.RetrieveSecretsWithOptions(cfg.AppID, &kmsClient.SecretsOptions{
		AttestationMethod: "gcp",
		ImageDigest:       claims.ImageDigest,
		RSAPrivateKeyPEM:  rsaPrivKeyPEM,
		RSAPublicKeyPEM:   rsaPubKeyPEM,
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve secrets: %w", err)
	}

	// Step 6: Decrypt using envManager (which handles JWE format)
	privateEnv, err := envMgr.DecryptSecretEnv(cfg.AppID, result.AppPrivateKey, encryptedEnvJWE)
	if err != nil {
		return fmt.Errorf("failed to decrypt environment: %w", err)
	}

	// Merge public and private env
	envVars := make(map[string]string)
	for k, v := range publicEnv {
		envVars[k] = v
	}
	for k, v := range privateEnv {
		envVars[k] = v
	}
```

## Key Integration Points

### 1. RSA Key Generation
From eigenx-kms-go, check if there's a helper:
- `crypto.GenerateRSAKeyPairPEM()` or similar
- OR use the old envclient crypto: `crypto.GenerateRSAKeyPair()`

### 2. Attestation JWT Generation
Use existing `envclient.ConfidentialSpaceTokenProvider`:
- Already implemented in `eigenx-kms-client/pkg/envclient/envclient.go`
- Connects to GCP Confidential Space via Unix socket
- Returns JWT with attestation claims

### 3. Image Digest Extraction
Options:
- Parse from GCP JWT using `attestation.VerifyAttestation`
- OR pass via CLI flag `--image-digest`
- OR extract from environment variable

## Critical Files to Modify

1. ✅ `eigenx-kms-client/internal/cli/flags.go` - Add AVS, operator-set-id, app-id, image-digest flags
2. ✅ `eigenx-kms-client/internal/cli/config.go` - Complete rewrite with new config fields
3. ✅ `eigenx-kms-client/cmd/kms-client/main.go` - Rewrite runClient to use kmsClient.Client
4. ✅ `eigenx-kms-client/go.mod` - Verify eigenx-kms-go dependency
5. ✅ `eigenx-kms-client/Dockerfile` - Update to build locally

## Files to Keep (No Changes)

- `eigenx-kms-client/pkg/envclient/envclient.go` - Keep ConfidentialSpaceTokenProvider only
- `eigenx-kms-client/pkg/envManager/envManager.go` - Keep if using on-chain env (optional)
- `eigenx-kms-client/pkg/contractCaller/` - Keep if using on-chain env (optional)
- `eigenx-kms-client/pkg/crypto/` - Keep for address derivation (if needed)
- `eigenx-kms-client/pkg/types/` - Keep for local type definitions

## Testing & Verification

### Build Test
```bash
cd eigenx-kms-client
go mod tidy
go build ./cmd/kms-client
```

### Docker Build Test
```bash
docker build -f eigenx-kms-client/Dockerfile eigenx-kms-client
```

### Runtime Test (Approach A: Operators provide env)
```bash
./eigenx-kms-client \
  --eth-rpc-url http://localhost:8545 \
  --avs-address 0x1234567890123456789012345678901234567890 \
  --operator-set-id 0 \
  --app-id my-app-id \
  --image-digest sha256:abc123... \
  --userapi-url http://localhost:3000 \
  --debug
```

Expected flow:
1. ✅ Generate GCP attestation JWT
2. ✅ Create kmsClient with blockchain config
3. ✅ Call RetrieveSecretsWithOptions with GCP attestation
4. ✅ Operators return encrypted env + encrypted partial signatures
5. ✅ Client decrypts partial sigs and recovers app private key
6. ✅ Client decrypts env using IBE
7. ✅ Output environment variables as JSON or export statements

### Runtime Test (Approach B: On-chain env registry)
```bash
./eigenx-kms-client \
  --eth-rpc-url http://localhost:8545 \
  --avs-address 0x1234... \
  --operator-set-id 0 \
  --app-id 0x5678... \
  --app-controller-address 0xABCD... \
  --userapi-url http://localhost:3000 \
  --debug
```

Expected flow:
1. ✅ Generate GCP attestation JWT and parse claims
2. ✅ Get encrypted env from AppController contract via envManager
3. ✅ Create kmsClient and call RetrieveSecretsWithOptions
4. ✅ Decrypt env using envManager.DecryptSecretEnv
5. ✅ Output combined public + private env vars

## Implementation Summary

### Core Changes
1. **Replace centralized KMS call** with distributed threshold cryptography
2. **Use `kmsClient.Client`** from eigenx-kms-go as the main integration point
3. **Keep GCP attestation** for proving TEE environment
4. **Support two modes**:
   - Operators provide encrypted env (simpler)
   - On-chain AppController provides env (more decentralized)

### What This Achieves
- ✅ Same CLI interface as old kms-client
- ✅ Distributed threshold cryptography (no single point of failure)
- ✅ GCP Confidential Space attestation (proves TEE execution)
- ✅ IBE encryption/decryption (Boneh-Franklin scheme)
- ✅ On-chain or operator-hosted encrypted env (flexible architecture)
- ✅ Local build (no git clone in Dockerfile)

## Decisions Made

1. ✅ **Env Source**: Use operators via `/secrets` endpoint (Approach A)
2. ✅ **Address Derivation**: YES - preserve old kms-client behavior (derive from mnemonic and post to user API)
3. ✅ **Image Digest**: Extract automatically from GCP JWT (like old kms-client)
4. ✅ **Build**: Local build, no external git clone

## Remaining Implementation Details

### RSA Key Pair Generation
Check if eigenx-kms-go/pkg/crypto has `GenerateRSAKeyPairPEM()`. If not, use the crypto from old envclient:

```go
// From eigenx-kms-client/pkg/crypto/crypto.go (if it exists)
rsaPrivKeyPEM, rsaPubKeyPEM, err := crypto.GenerateRSAKeyPair()
```

### GCP Project ID
For attestation verification, need to know the GCP project ID. Options:
- Read from environment variable `GCP_PROJECT_ID`
- Add CLI flag `--gcp-project-id`
- OR skip full JWT verification and just extract claims without verification

### Address Derivation Integration
The old kms-client uses:
```go
crypto.DeriveAddressesFromMnemonic(mnemonic, numAddresses)
```

This should be preserved from eigenx-kms-client/pkg/crypto if it exists, matching the old kms-client behavior.
