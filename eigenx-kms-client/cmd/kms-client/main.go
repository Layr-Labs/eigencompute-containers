package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	kmscli "github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/internal/cli"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/clients/ethereumClient"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/envManager"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/envclient"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/logger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "eigenx-kms-client",
		Usage: "Fetch environment variables from an EigenX KMS server (with attestation)",
		Flags: []cli.Flag{
			kmscli.ETHRpcURLFlag,
			kmscli.KMSSigningKeyFileFlag,
			kmscli.AppIDFlag,
			kmscli.LogLevelFlag,
			kmscli.OutputFileFlag,
			kmscli.UserAPIURLFlag,
		},
		Action: runClient,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func runClient(c *cli.Context) error {
	ctx := context.Background()
	cfg := kmscli.NewConfigFromCLI(c)

	l, err := logger.NewLogger(&logger.LoggerConfig{
		Debug: cfg.Debug,
	})
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	ethClient, err := ethereumClient.GetEthClient(cfg.ETHRPRCUrl)
	if err != nil {
		return fmt.Errorf("failed to create Ethereum client: %w", err)
	}

	chainId, err := ethClient.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %w", err)
	}

	cc, err := caller.NewContractCaller(ethClient, &caller.ContractsConfig{
		AppControllerAddress: common.Address{}, // TODO
	}, l)

	envMan, err := envManager.NewEnvManager(l, cc)
	if err != nil {
		return fmt.Errorf("failed to create env manager: %w", err)
	}

	l.Sugar().Debugw("Reading KMS signing key", "file", cfg.KMSSigningKey)
	kmsSigningKeyBytes, err := os.ReadFile(cfg.KMSSigningKey)
	if err != nil {
		return fmt.Errorf("failed to read KMS signing key: %w", err)
	}

	tokenProvider := envclient.NewConfidentialSpaceTokenProvider(l)
	client := envclient.NewEnvClient(l, tokenProvider, kmsSigningKeyBytes, cfg.ServerURL, cfg.UserAPIURL)

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
