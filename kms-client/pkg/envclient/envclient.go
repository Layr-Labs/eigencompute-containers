package envclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigenx-kms-client/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-client/pkg/types"
	"github.com/cenkalti/backoff/v5"
)

const (
	initialInterval       = 500 * time.Millisecond
	maxInterval           = 5 * time.Second
	multiplier            = 1.5
	maxElapsedTime        = 2 * time.Minute
	attestationSocketPath = "/run/container_launcher/teeserver.sock"
	boundEvidenceURL      = "http://localhost/v1/bound_evidence"
)

// AttestationProvider interface for generating raw attestation bytes.
type AttestationProvider interface {
	GetAttestation(ctx context.Context, challenge []byte) ([]byte, error)
}

// boundEvidenceRequest represents the request to the bound evidence endpoint.
type boundEvidenceRequest struct {
	Challenge string `json:"challenge"`
}

// BoundEvidenceProvider implements AttestationProvider by calling /v1/bound_evidence on the attestation unix socket.
type BoundEvidenceProvider struct {
	logger *slog.Logger
}

func NewBoundEvidenceProvider(logger *slog.Logger) *BoundEvidenceProvider {
	return &BoundEvidenceProvider{logger: logger}
}

func (p *BoundEvidenceProvider) GetAttestation(ctx context.Context, challenge []byte) ([]byte, error) {
	reqBody, err := json.Marshal(boundEvidenceRequest{
		Challenge: base64.StdEncoding.EncodeToString(challenge),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bound evidence request: %w", err)
	}

	// Create HTTP client that uses Unix socket
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", attestationSocketPath)
			},
		},
	}

	p.logger.Debug("Requesting bound evidence attestation")

	req, err := http.NewRequestWithContext(ctx, "POST", boundEvidenceURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create bound evidence request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request bound evidence: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bound evidence service returned status %d: %s", resp.StatusCode, string(body))
	}

	attestationBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read bound evidence response: %w", err)
	}

	p.logger.Info("Successfully obtained bound evidence attestation", "attestation_length", len(attestationBytes))

	return attestationBytes, nil
}

type EnvClient struct {
	Logger              *slog.Logger
	attestationProvider AttestationProvider
	kmsSigningKey       []byte
	serverURL           string
	userAPIURL          string
}

func NewEnvClient(logger *slog.Logger, attestationProvider AttestationProvider, kmsSigningKey []byte, serverURL string, userAPIURL string) *EnvClient {
	return &EnvClient{
		Logger:              logger,
		attestationProvider: attestationProvider,
		kmsSigningKey:       kmsSigningKey,
		serverURL:           serverURL,
		userAPIURL:          userAPIURL,
	}
}

func (e *EnvClient) GetEnv(ctx context.Context) ([]byte, error) {
	// Generate RSA key pair on the fly
	e.Logger.Info("Generating RSA key pair")
	rsaPrivateKeyPEM, rsaPublicKeyPEM, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	e.Logger.Debug("RSA key pair generated", "public_key_length", len(rsaPublicKeyPEM))

	// Calculate RSA key hash for challenge
	rsaKeyHash := crypto.CalculateSignableDigest(crypto.EnvRequestRSAKeyHeader, rsaPublicKeyPEM)

	// Request raw attestation with RSA key hash as challenge
	e.Logger.Info("Requesting attestation")
	attestationBytes, err := e.attestationProvider.GetAttestation(ctx, rsaKeyHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation: %w", err)
	}

	// Send request to server with base64-encoded attestation and RSA public key
	attestationBase64 := base64.StdEncoding.EncodeToString(attestationBytes)
	e.Logger.Debug("Sending request to server", "url", e.serverURL)
	response, err := e.sendRequest(ctx, types.EnvRequestV3{
		Attestation: attestationBase64,
		RSAKeyPEM:   string(rsaPublicKeyPEM),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	e.Logger.Info("Received response from server")

	// Verify signature
	e.Logger.Debug("Verifying response signature")
	isValid, err := crypto.VerifyKMSSignature(*response, e.kmsSigningKey)
	if err != nil {
		return nil, fmt.Errorf("signature verification error: %w", err)
	}
	if !isValid {
		return nil, fmt.Errorf("invalid signature")
	}

	e.Logger.Info("Signature verified successfully")

	e.Logger.Debug("Response", "response", response.Data)

	// Decrypt response
	e.Logger.Debug("Decrypting response")
	rsaPrivateKey, err := crypto.RSAPrivateKeyFromPEM(rsaPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	envJSONBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(rsaPrivateKey, []byte(response.Data.EncryptedCombinedEnv))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %w", err)
	}

	e.Logger.Info("Response decrypted successfully")

	envVars := make(map[string]string)
	if err := json.Unmarshal(envJSONBytes, &envVars); err != nil {
		return nil, fmt.Errorf("failed to unmarshal env JSON: %w", err)
	}

	// Derive addresses to log
	evmAddresses, solanaAddresses, err := crypto.DeriveAddressesFromMnemonic(envVars[types.MnemonicEnvVarName], types.NumAddressesToDerive)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address for logging: %w", err)
	}

	addresses := types.AddressesResponseV1{
		EVMAddresses:    evmAddresses,
		SolanaAddresses: solanaAddresses,
	}
	addressBytes, err := json.Marshal(addresses)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal addresses for logging: %w", err)
	}
	e.Logger.Info("Derived addresses from mnemonic", "addresses", string(addressBytes))

	// Upload raw attestation to user API (non-fatal)
	challengeHex := hex.EncodeToString(rsaKeyHash)
	e.Logger.Info("Posting attestation to user API", "url", e.userAPIURL)
	if err := e.postAttestationToUserAPI(ctx, attestationBase64, challengeHex, ""); err != nil {
		e.Logger.Error("Failed to post attestation to user API after retries", "error", err)
	} else {
		e.Logger.Info("Successfully posted attestation to user API")
	}

	return envJSONBytes, nil
}

// Attest requests an attestation JWT from the KMS server.
func (e *EnvClient) Attest(ctx context.Context) (string, error) {
	// Generate RSA key pair on the fly
	e.Logger.Info("Generating RSA key pair for attestation")
	_, rsaPublicKeyPEM, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Calculate RSA key hash for challenge
	rsaKeyHash := crypto.CalculateSignableDigest(crypto.EnvRequestRSAKeyHeader, rsaPublicKeyPEM)

	// Request raw attestation with RSA key hash as challenge
	e.Logger.Info("Requesting attestation")
	attestationBytes, err := e.attestationProvider.GetAttestation(ctx, rsaKeyHash)
	if err != nil {
		return "", fmt.Errorf("failed to get attestation: %w", err)
	}

	// Send request to server with base64-encoded attestation and RSA public key
	attestationBase64 := base64.StdEncoding.EncodeToString(attestationBytes)
	e.Logger.Debug("Sending attest request to server", "url", e.serverURL)
	response, err := e.sendAttestRequest(ctx, types.AttestRequest{
		Version:     3,
		Attestation: attestationBase64,
		RSAKeyPEM:   string(rsaPublicKeyPEM),
	})
	if err != nil {
		return "", fmt.Errorf("failed to send attest request: %w", err)
	}

	e.Logger.Info("Received attest response from server")

	// Verify signature
	e.Logger.Debug("Verifying response signature")
	isValid, err := crypto.VerifyKMSSignature(*response, e.kmsSigningKey)
	if err != nil {
		return "", fmt.Errorf("signature verification error: %w", err)
	}
	if !isValid {
		return "", fmt.Errorf("invalid signature")
	}

	e.Logger.Info("Signature verified successfully")

	return response.Data.Token, nil
}

func (e *EnvClient) retryHTTPRequest(ctx context.Context, logMessage string, operation func() ([]byte, error)) ([]byte, error) {
	retries := 0
	wrappedOperation := func() ([]byte, error) {
		e.Logger.Info(logMessage, "retries", retries)
		retries++
		return operation()
	}

	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.InitialInterval = initialInterval
	exponentialBackoff.MaxInterval = maxInterval
	exponentialBackoff.Multiplier = multiplier

	return backoff.Retry(ctx, wrappedOperation, backoff.WithBackOff(exponentialBackoff), backoff.WithMaxElapsedTime(maxElapsedTime))
}

func (e *EnvClient) sendRequest(ctx context.Context, envRequest types.EnvRequestV3) (*types.SignedResponse[types.EnvResponseV3], error) {
	requestBody, err := json.Marshal(envRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal env request: %w", err)
	}

	url := e.serverURL + "/env/v3"
	client := &http.Client{Timeout: 30 * time.Second}

	operation := func() ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(responseBody))
		}
		if resp.StatusCode != http.StatusOK {
			return nil, backoff.Permanent(fmt.Errorf("client error %d: %s", resp.StatusCode, string(responseBody)))
		}

		return responseBody, nil
	}

	responseBody, err := e.retryHTTPRequest(ctx, "Requesting env from server...", operation)
	if err != nil {
		return nil, fmt.Errorf("failed to send request after retries: %w", err)
	}

	var signedResponse types.SignedResponse[types.EnvResponseV3]
	if err := json.Unmarshal(responseBody, &signedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &signedResponse, nil
}

func (e *EnvClient) sendAttestRequest(ctx context.Context, attestRequest types.AttestRequest) (*types.SignedResponse[types.AttestResponse], error) {
	requestBody, err := json.Marshal(attestRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attest request: %w", err)
	}

	url := e.serverURL + "/auth/attest"
	client := &http.Client{Timeout: 30 * time.Second}

	operation := func() ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(responseBody))
		}
		if resp.StatusCode != http.StatusOK {
			return nil, backoff.Permanent(fmt.Errorf("client error %d: %s", resp.StatusCode, string(responseBody)))
		}

		return responseBody, nil
	}

	responseBody, err := e.retryHTTPRequest(ctx, "Requesting attestation JWT from server...", operation)
	if err != nil {
		return nil, fmt.Errorf("failed to send attest request after retries: %w", err)
	}

	var signedResponse types.SignedResponse[types.AttestResponse]
	if err := json.Unmarshal(responseBody, &signedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &signedResponse, nil
}

func (e *EnvClient) postAttestationToUserAPI(ctx context.Context, attestationBase64 string, challenge string, extraData string) error {
	payload := map[string]string{
		"attestation": attestationBase64,
		"challenge":   challenge,
		"extra_data":  extraData,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation payload: %w", err)
	}

	url := e.userAPIURL + "/v2/attestation"
	client := &http.Client{Timeout: 30 * time.Second}

	operation := func() ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payloadBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(responseBody))
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return nil, backoff.Permanent(fmt.Errorf("client error %d: %s", resp.StatusCode, string(responseBody)))
		}

		e.Logger.Debug("User API attestation response", "status", resp.StatusCode, "body", string(responseBody))
		return responseBody, nil
	}

	_, err = e.retryHTTPRequest(ctx, "Posting attestation to user API...", operation)
	if err != nil {
		return fmt.Errorf("failed to post attestation after retries: %w", err)
	}

	return nil
}
