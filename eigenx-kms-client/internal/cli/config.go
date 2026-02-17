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
	LogLevel             string
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
		LogLevel:             c.String(LogLevelFlag.Name),
	}
}

func NewLogger(level string) (*zap.Logger, error) {
	var zapLevel zap.AtomicLevel
	switch level {
	case "debug":
		zapLevel = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "warn":
		zapLevel = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		zapLevel = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		zapLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zapLevel
	return cfg.Build()
}
