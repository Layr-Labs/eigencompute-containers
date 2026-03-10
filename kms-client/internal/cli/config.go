package cli

import (
	"log/slog"
	"os"

	"github.com/urfave/cli/v2"
)

type Config struct {
	ServerURL     string
	KMSSigningKey string
	LogLevel      string
	AppID         string
	OutputFile    string
	UserAPIURL    string
	Logger        *slog.Logger
}

func GetLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type AttestConfig struct {
	ServerURL     string
	KMSSigningKey string
	LogLevel      string
	OutputFile    string
	Audience      string
	Logger        *slog.Logger
}

func NewConfigFromCLI(c *cli.Context) *Config {
	cfg := &Config{
		ServerURL:     c.String(KMSServerURLFlag.Name),
		KMSSigningKey: c.String(KMSSigningKeyFileFlag.Name),
		LogLevel:      c.String(LogLevelFlag.Name),
		AppID:         c.String(AppIDFlag.Name),
		OutputFile:    c.String(OutputFileFlag.Name),
		UserAPIURL:    c.String(UserAPIURLFlag.Name),
	}

	cfg.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: GetLogLevel(cfg.LogLevel)}))
	return cfg
}

func NewAttestConfigFromCLI(c *cli.Context) *AttestConfig {
	cfg := &AttestConfig{
		ServerURL:     c.String(KMSServerURLFlag.Name),
		KMSSigningKey: c.String(KMSSigningKeyFileFlag.Name),
		LogLevel:      c.String(LogLevelFlag.Name),
		OutputFile:    c.String(OutputFileFlag.Name),
		Audience:      c.String(AudienceFlag.Name),
	}

	cfg.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: GetLogLevel(cfg.LogLevel)}))
	return cfg
}


