package cli

import (
	"github.com/urfave/cli/v2"
)

type Config struct {
	ServerURL     string
	KMSSigningKey string
	AppID         string
	OutputFile    string
	UserAPIURL    string
	ETHRPRCUrl    string
	Debug         bool
}

func NewConfigFromCLI(c *cli.Context) *Config {
	cfg := &Config{
		ETHRPRCUrl:    c.String(ETHRpcURLFlag.Name),
		Debug:         c.Bool(Debug.Name),
		KMSSigningKey: c.String(KMSSigningKeyFileFlag.Name),
		AppID:         c.String(AppIDFlag.Name),
		OutputFile:    c.String(OutputFileFlag.Name),
		UserAPIURL:    c.String(UserAPIURLFlag.Name),
	}

	return cfg
}
