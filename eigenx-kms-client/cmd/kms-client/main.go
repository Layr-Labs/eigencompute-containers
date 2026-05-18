package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	kmscli "github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/internal/cli"
	localcrypto "github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/crypto"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/envclient"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/types"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func main() {
	app := &cli.App{
		Name:  "eigenx-kms-client",
		Usage: "Fetch environment variables from an EigenX KMS server (with attestation)",
		Flags: []cli.Flag{
			kmscli.ETHRpcURLFlag,
			kmscli.AVSAddressFlag,
			kmscli.OperatorSetIDFlag,
			kmscli.LogLevelFlag,
		},
		Commands: []*cli.Command{
			{
				Name:  "encrypt",
				Usage: "Encrypt data for an application using IBE",
				Flags: []cli.Flag{
					kmscli.AppIDRequiredFlag,
					kmscli.DataFlag,
					kmscli.OutputFileFlag,
				},
				Action: encryptCommand,
			},
			{
				Name:  "decrypt",
				Usage: "Decrypt data by collecting partial signatures from KMS operators",
				Flags: []cli.Flag{
					kmscli.AppIDRequiredFlag,
					kmscli.KMSSigningKeyFileFlag,
					kmscli.OutputFileFlag,
					kmscli.UserAPIURLFlag,
					kmscli.AppControllerAddressFlag,
				},
				Action: decryptCommand,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// createClient creates a KMS client from CLI context using the global flags.
func createClient(c *cli.Context, l *zap.Logger) (*kmsClient.Client, error) {
	ethClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   c.String("eth-rpc-url"),
		BlockType: ethereum.BlockType_Latest,
	}, l)

	l1Client, err := ethClient.GetEthereumContractCaller()
	if err != nil {
		return nil, fmt.Errorf("failed to get Ethereum contract caller: %w", err)
	}

	contractCaller, err := caller.NewContractCaller(l1Client, nil, l)
	if err != nil {
		return nil, fmt.Errorf("failed to create contract caller: %w", err)
	}

	return kmsClient.NewClient(&kmsClient.ClientConfig{
		AVSAddress:     c.String("avs-address"),
		OperatorSetID:  uint32(c.Uint("operator-set-id")),
		Logger:         l,
		ContractCaller: contractCaller,
	})
}

// encryptCommand handles the encrypt subcommand.
// Fetches the master public key from operator set and encrypts data using IBE.
func encryptCommand(c *cli.Context) error {
	logLevel := c.String("log-level")
	l, err := kmscli.NewLogger(logLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	appID := c.String("app-id")
	data := c.String("data")
	outputFile := c.String("output")

	l.Sugar().Infow("Encrypting data for app", "app_id", appID)

	client, err := createClient(c, l)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	operators, err := client.GetOperators()
	if err != nil {
		return fmt.Errorf("failed to get operators: %w", err)
	}

	encryptedData, err := client.Encrypt(appID, []byte(data), operators)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	encryptedHex := hexutil.Encode(encryptedData)
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(encryptedHex), 0600); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		l.Sugar().Infow("Encrypted data written to file", "path", outputFile)
	} else {
		fmt.Println(encryptedHex)
	}

	return nil
}

// decryptCommand handles the decrypt subcommand.
// Full TEE workflow: attestation, threshold key recovery, IBE decryption, address derivation, user API posting.
func decryptCommand(c *cli.Context) error {
	ctx := context.Background()
	cfg := kmscli.NewConfigFromCLI(c)

	l, err := kmscli.NewLogger(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	isDebug := cfg.LogLevel == "debug"

	// Read and validate KMS signing key
	l.Sugar().Debugw("Reading KMS signing key", "file", cfg.KMSSigningKey)
	kmsSigningKeyBytes, err := os.ReadFile(cfg.KMSSigningKey)
	if err != nil {
		return fmt.Errorf("failed to read KMS signing key: %w", err)
	}

	kmsSigningKey, err := localcrypto.ParseKMSSigningKey(kmsSigningKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse KMS signing key: %w", err)
	}
	l.Sugar().Infow("KMS signing key loaded successfully")

	// Step 1: Generate ephemeral RSA key pair for encrypting partial signatures
	l.Sugar().Info("Generating RSA key pair for secure transport")
	rsaPrivKeyPEM, rsaPubKeyPEM, err := generateRSAKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Step 2: Generate GCP attestation JWT with nonce
	l.Sugar().Info("Requesting GCP Confidential Space attestation")
	tokenProvider := envclient.NewConfidentialSpaceTokenProvider(l)

	// Use RSA public key hash as nonce (matches old kms-client pattern)
	rsaKeyHash := localcrypto.CalculateSignableDigest(localcrypto.EnvRequestRSAKeyHeader, rsaPubKeyPEM)
	rsaKeyHashHex := hex.EncodeToString(rsaKeyHash)

	gcpJWT, err := tokenProvider.GetToken(ctx, types.KMSJWTAudience, rsaKeyHashHex)
	if err != nil {
		return fmt.Errorf("failed to get GCP attestation: %w", err)
	}

	// Step 3: Parse JWT to extract image digest automatically
	l.Sugar().Info("Parsing attestation claims from GCP JWT")

	// Get GCP project ID from environment
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		projectID = "eigenx-compute" // Default
		l.Sugar().Warn("GCP_PROJECT_ID not set, using default", "project_id", projectID)
	}

	// Create slog logger for attestation verifier (it requires slog, not zap)
	var slogLogger *slog.Logger
	if isDebug {
		slogLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		slogLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	verifier, err := attestation.NewAttestationVerifier(ctx, slogLogger, projectID, 15*time.Minute, isDebug)
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

	// Step 4: Create KMS client
	l.Sugar().Infow("Connecting to Ethereum", "rpc", cfg.ETHRpcURL)
	kmsClientInstance, err := createClient(c, l)
	if err != nil {
		return fmt.Errorf("failed to create KMS client: %w", err)
	}

	// Step 5: Retrieve secrets using distributed KMS with GCP attestation
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

	// Step 5b: Verify secrets result integrity using KMS signing key
	l.Sugar().Info("Verifying secrets result integrity")
	if err := localcrypto.VerifySecretsResult(kmsSigningKey, result.EncryptedEnv, result.PublicEnv, result.ResponseCount, result.ThresholdNeeded); err != nil {
		return fmt.Errorf("secrets result verification failed: %w", err)
	}
	l.Sugar().Info("Secrets result verification passed")

	// Step 6: Decrypt environment data using recovered app private key
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

	// Step 7: Parse environment JSON
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

	// Step 8: Derive addresses from mnemonic and post to user API
	if mnemonic, ok := envVars[types.MnemonicEnvVarName]; ok && cfg.UserAPIURL != "" {
		l.Sugar().Info("Deriving addresses from mnemonic")

		evmAddrs, solanaAddrs, err := deriveAddresses(mnemonic, types.NumAddressesToDerive)
		if err != nil {
			l.Sugar().Warnw("Failed to derive addresses", "error", err)
		} else {
			// Marshal addresses to AddressesResponseV1
			addresses := types.AddressesResponseV1{
				EVMAddresses:    evmAddrs,
				SolanaAddresses: solanaAddrs,
			}
			addressBytes, err := json.Marshal(addresses)
			if err != nil {
				l.Sugar().Warnw("Failed to marshal addresses", "error", err)
			} else {
				l.Sugar().Info("Derived addresses from mnemonic", "addresses", string(addressBytes))

				// Calculate nonce from address JSON
				addrNonce := calculateAddressNonce(evmAddrs, solanaAddrs)

				// Get attestation JWT with address nonce
				addressJWT, err := tokenProvider.GetToken(ctx, types.DashboardJWTAudience, addrNonce)
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
	}

	// Step 9: Output environment variables
	envJSONBytes, _ := json.Marshal(envVars)

	if cfg.OutputFile != "" {
		return writeEnvFile(cfg, envJSONBytes)
	}

	pretty, _ := json.MarshalIndent(envVars, "", "  ")
	fmt.Printf("%s\n", string(pretty))
	return nil
}

func writeEnvFile(cfg *kmscli.Config, envJSONBytes []byte) error {
	envVars := make(map[string]string)
	if err := json.Unmarshal(envJSONBytes, &envVars); err != nil {
		return fmt.Errorf("failed to unmarshal env: %w", err)
	}

	var lines []string
	for key, value := range envVars {
		lines = append(lines, fmt.Sprintf("export %s=\"%s\"", key, value))
	}
	sort.Strings(lines)

	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(cfg.OutputFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	// Successfully wrote file (logging removed for Milestone 1)
	return nil
}

// postJWTToUserAPI posts an attestation JWT to the user API
// Matches pattern from kms-client/pkg/envclient/envclient.go
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

// generateRSAKeyPair generates a 4096-bit RSA key pair for encrypting partial signatures in transit
// Matches pattern from kms-client/pkg/crypto/crypto.go - uses 4096 bits
func generateRSAKeyPair() ([]byte, []byte, error) {
	// Use eigenx-kms-go/pkg/encryption with 4096 bits (matching old kms-client)
	privKeyPEM, pubKeyPEM, err := encryption.GenerateKeyPair(4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}
	return privKeyPEM, pubKeyPEM, nil
}

// deriveAddresses derives EVM and Solana addresses from a mnemonic
// Returns structured types to match kms-client pattern
func deriveAddresses(mnemonic string, count int) ([]types.EVMAddressAndDerivationPath, []types.SolanaAddressAndDerivationPath, error) {
	return localcrypto.DeriveAddressesFromMnemonic(mnemonic, count)
}

// calculateAddressNonce creates a nonce from derived addresses for attestation
// Matches pattern from kms-client/pkg/envclient/envclient.go
func calculateAddressNonce(evmAddrs []types.EVMAddressAndDerivationPath, solanaAddrs []types.SolanaAddressAndDerivationPath) string {
	// Marshal addresses into AddressesResponseV1 format (same as old kms-client)
	addresses := types.AddressesResponseV1{
		EVMAddresses:    evmAddrs,
		SolanaAddresses: solanaAddrs,
	}
	addressBytes, _ := json.Marshal(addresses)

	// Calculate digest with AppDerivedAddressesHeader
	digest := localcrypto.CalculateSignableDigest(localcrypto.AppDerivedAddressesHeader, addressBytes)
	return hex.EncodeToString(digest)
}
