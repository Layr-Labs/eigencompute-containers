package cli

import (
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

type Config struct {
	ETHRpcURL            string
	AVSAddress           string
	OperatorSetID        uint32
	AppID                string
	AppControllerAddress string
	KMSSigningKey        string
	OutputFile           string
	UserAPIURL           string
	Debug                bool
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
