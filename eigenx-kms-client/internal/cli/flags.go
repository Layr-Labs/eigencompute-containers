package cli

import "github.com/urfave/cli/v2"

var (
	ETHRpcURLFlag = &cli.StringFlag{
		Name:     "eth-rpc-url",
		Usage:    "Ethereum RPC URL (e.g. http://localhost:8545)",
		Required: true,
		EnvVars:  []string{"ETH_RPC_URL"},
	}

	Debug = &cli.BoolFlag{
		Name:    "debug",
		Usage:   "Enable debug mode",
		EnvVars: []string{"DEBUG"},
	}

	KMSSigningKeyFileFlag = &cli.StringFlag{
		Name:     "kms-signing-key-file",
		Usage:    "Path to KMS signing public key PEM file",
		Value:    "kms-signing-public-key.pem",
		EnvVars:  []string{"KMS_SIGNING_KEY_FILE"},
		Required: true,
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
)
