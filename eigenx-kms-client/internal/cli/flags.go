package cli

import "github.com/urfave/cli/v2"

var (
	ETHRpcURLFlag = &cli.StringFlag{
		Name:     "eth-rpc-url",
		Usage:    "Ethereum RPC URL (e.g. http://localhost:8545)",
		Required: true,
		EnvVars:  []string{"ETH_RPC_URL"},
	}

	KMSSigningKeyFileFlag = &cli.StringFlag{
		Name:     "kms-signing-key-file",
		Usage:    "Path to KMS signing public key PEM file",
		Value:    "kms-signing-public-key.pem",
		EnvVars:  []string{"KMS_SIGNING_KEY_FILE"},
		Required: true,
	}

	LogLevelFlag = &cli.StringFlag{
		Name:    "log-level",
		Value:   "info",
		Usage:   "Log level (debug, info, warn, error)",
		EnvVars: []string{"LOG_LEVEL"},
	}

	AppIDFlag = &cli.StringFlag{
		Name:    "app-id",
		Usage:   "App ID to spoof (debug mode only)",
		EnvVars: []string{"APP_ID"},
	}

	OutputFileFlag = &cli.StringFlag{
		Name:  "output",
		Usage: "Output file path to write environment variables as export KEY=\"VALUE\" lines",
	}

	UserAPIURLFlag = &cli.StringFlag{
		Name:     "userapi-url",
		Usage:    "User API URL to POST attestation JWT",
		EnvVars:  []string{"USERAPI_URL"},
		Required: true,
	}
)
