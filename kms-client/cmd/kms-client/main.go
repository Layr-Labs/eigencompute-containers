package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	kmscli "github.com/Layr-Labs/eigenx-kms-client/internal/cli"
	"github.com/Layr-Labs/eigenx-kms-client/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-client/pkg/envclient"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "kms-client",
		Usage: "Fetch environment variables from an EigenX KMS server (with attestation)",
		Flags: []cli.Flag{
			kmscli.KMSServerURLFlag,
			kmscli.KMSSigningKeyFileFlag,
			kmscli.AppIDFlag,
			kmscli.LogLevelFlag,
			kmscli.OutputFileFlag,
			kmscli.UserAPIURLFlag,
		},
		Action: runClient,
		Commands: []*cli.Command{
			{
				Name:  "attest",
				Usage: "Request an attestation JWT from the KMS server",
				Flags: []cli.Flag{
					kmscli.AudienceFlag,
				},
				Action: runAttest,
			},
			{
				Name:  "derive-storage-key",
				Usage: "Derive a 32-byte LUKS volume key from the KMS-issued mnemonic and write it (hex-encoded) to a file",
				Description: `Fetches the BIP39 mnemonic from KMS via the same attestation flow used
by the default command, then derives a 32-byte storage encryption key
using the EIGENX_STORAGE_KEY_DERIVATION_V1 scheme. Output is hex-encoded
ASCII (64 chars + newline) at mode 0600.

The derivation is intentionally identical to:
  - github.com/Layr-Labs/eigenx-kms's DeriveStorageKey
  - github.com/Layr-Labs/go-tpm-tools launcher's DeriveStorageKey
so a PD LUKS-formatted by either side can be opened by any of the
others. Used by the user-container entrypoint script
(compute-source-env.sh.tmpl in Layr-Labs/ecloud) on prewarm-detach
upgrades, where the launcher defers storage setup to the script via
tee-await-late-attach=true.

The output file is the caller's responsibility to remove after use;
this binary takes no view on lifecycle.`,
				Flags: []cli.Flag{
					kmscli.StorageKeyOutputFileFlag,
				},
				Action: runDeriveStorageKey,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func runClient(c *cli.Context) error {
	ctx := context.Background()
	cfg := kmscli.NewConfigFromCLI(c)

	if cfg.UserAPIURL == "" {
		return fmt.Errorf("--userapi-url is required")
	}

	cfg.Logger.Debug("Reading KMS signing key", "file", cfg.KMSSigningKey)
	kmsSigningKeyBytes, err := os.ReadFile(cfg.KMSSigningKey)
	if err != nil {
		return fmt.Errorf("failed to read KMS signing key: %w", err)
	}

	attestationProvider := envclient.NewBoundEvidenceProvider(cfg.Logger)
	client := envclient.NewEnvClient(cfg.Logger, attestationProvider, kmsSigningKeyBytes, cfg.ServerURL, cfg.UserAPIURL)

	envJSONBytes, err := client.GetEnv(ctx)
	if err != nil {
		return fmt.Errorf("failed to get env: %w", err)
	}

	if cfg.OutputFile != "" {
		return writeEnvFile(cfg, envJSONBytes)
	}

	pretty, _ := json.MarshalIndent(json.RawMessage(envJSONBytes), "", "  ")
	fmt.Printf("%s\n", string(pretty))
	return nil
}

func runAttest(c *cli.Context) error {
	ctx := context.Background()
	cfg := kmscli.NewAttestConfigFromCLI(c)

	cfg.Logger.Debug("Reading KMS signing key", "file", cfg.KMSSigningKey)
	kmsSigningKeyBytes, err := os.ReadFile(cfg.KMSSigningKey)
	if err != nil {
		return fmt.Errorf("failed to read KMS signing key: %w", err)
	}

	attestationProvider := envclient.NewBoundEvidenceProvider(cfg.Logger)
	client := envclient.NewEnvClient(cfg.Logger, attestationProvider, kmsSigningKeyBytes, cfg.ServerURL, "")

	token, err := client.Attest(ctx, cfg.Audience)
	if err != nil {
		return fmt.Errorf("failed to get attestation JWT: %w", err)
	}

	if cfg.OutputFile != "" {
		if err := os.WriteFile(cfg.OutputFile, []byte(token), 0600); err != nil {
			return fmt.Errorf("failed to write token to file: %w", err)
		}
		cfg.Logger.Info("Attestation JWT written to file", "file", cfg.OutputFile)
		return nil
	}

	fmt.Println(token)
	return nil
}

// runDeriveStorageKey fetches the mnemonic from KMS (same attestation flow
// as the default command) and writes a hex-encoded 32-byte LUKS key to the
// configured output file. It deliberately does NOT support stdout output:
// the key bytes are sensitive enough that a stray `--output ""` typo
// shouldn't leak them into shell history or terminal scrollback. The
// StorageKeyOutputFileFlag is Required for the same reason.
//
// Mnemonic handling: the BIP39 string is held in memory only for the duration
// of DeriveStorageKey, which zeros the intermediate seed before returning.
// The map returned by GetEnv still contains MNEMONIC after this function
// completes — callers that don't need the mnemonic afterwards should drop
// the reference, but this binary exits immediately so GC reclaim is moot.
func runDeriveStorageKey(c *cli.Context) error {
	ctx := context.Background()
	cfg := kmscli.NewConfigFromCLI(c)
	if cfg.UserAPIURL == "" {
		return fmt.Errorf("--userapi-url is required")
	}
	outputFile := c.String(kmscli.StorageKeyOutputFileFlag.Name)

	cfg.Logger.Debug("Reading KMS signing key", "file", cfg.KMSSigningKey)
	kmsSigningKeyBytes, err := os.ReadFile(cfg.KMSSigningKey)
	if err != nil {
		return fmt.Errorf("failed to read KMS signing key: %w", err)
	}

	attestationProvider := envclient.NewBoundEvidenceProvider(cfg.Logger)
	client := envclient.NewEnvClient(cfg.Logger, attestationProvider, kmsSigningKeyBytes, cfg.ServerURL, cfg.UserAPIURL)

	envJSONBytes, err := client.GetEnv(ctx)
	if err != nil {
		return fmt.Errorf("failed to get env: %w", err)
	}

	envVars := make(map[string]string)
	if err := json.Unmarshal(envJSONBytes, &envVars); err != nil {
		return fmt.Errorf("failed to unmarshal env: %w", err)
	}

	mnemonic, ok := envVars["MNEMONIC"]
	if !ok || mnemonic == "" {
		return fmt.Errorf("KMS env response missing MNEMONIC; cannot derive storage key")
	}

	key, err := crypto.DeriveStorageKey(mnemonic)
	if err != nil {
		return fmt.Errorf("failed to derive storage key: %w", err)
	}
	defer crypto.ZeroBytes(key)

	// Hex-encode and append a trailing newline so cryptsetup's `--key-file`
	// reads the full 64 hex chars unambiguously (cryptsetup reads up to the
	// first newline OR end-of-file; a no-newline file works too, but a
	// terminating newline is the standard convention for line-oriented
	// secrets files).
	encoded := hex.EncodeToString(key) + "\n"

	// O_EXCL prevents silently overwriting an attacker-planted symlink
	// pointing at a sensitive file. If the caller wants to overwrite an
	// existing key file they should rm -f it first; making this an error
	// surfaces accidental reuse early.
	f, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create storage key file %s: %w", outputFile, err)
	}
	defer f.Close()
	if _, err := f.WriteString(encoded); err != nil {
		return fmt.Errorf("failed to write storage key file %s: %w", outputFile, err)
	}

	cfg.Logger.Info("Storage key derived and written", "file", outputFile)
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

	cfg.Logger.Info("Environment variables written to file", "file", cfg.OutputFile, "count", len(envVars))
	return nil
}
