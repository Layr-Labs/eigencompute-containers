package envclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/crypto"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/types"
	"github.com/cenkalti/backoff/v5"
	"go.uber.org/zap"
)

const (
	initialInterval       = 500 * time.Millisecond
	maxInterval           = 5 * time.Second
	multiplier            = 1.5
	maxElapsedTime        = 2 * time.Minute
	attestationSocketPath = "/run/container_launcher/teeserver.sock"
	attestationTokenURL   = "http://localhost/v1/intel/token"
)

// AttestationTokenProvider generates an attestation token for a given audience + nonce.
type AttestationTokenProvider interface {
	GetToken(ctx context.Context, audience, nonce string) (string, error)
}

// ConfidentialSpaceTokenProvider implements AttestationTokenProvider via GCP Confidential Space.
// Reference:
// https://cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources#retrieve_attestation_tokens
type ConfidentialSpaceTokenProvider struct {
	logger *zap.Logger
}

func NewConfidentialSpaceTokenProvider(logger *zap.Logger) *ConfidentialSpaceTokenProvider {
	return &ConfidentialSpaceTokenProvider{logger: logger}
}

type attestationTokenRequest struct {
	Audience  string   `json:"audience"`
	TokenType string   `json:"token_type"`
	Nonces    []string `json:"nonces"`
}

func (p *ConfidentialSpaceTokenProvider) GetToken(ctx context.Context, audience, nonce string) (string, error) {
	tokenReq := attestationTokenRequest{
		Audience:  audience,
		TokenType: "OIDC",
		Nonces:    []string{nonce},
	}

	reqBody, err := json.Marshal(tokenReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token request: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", attestationSocketPath)
			},
		},
	}

	p.logger.Sugar().Debugw("Requesting attestation token", "audience", audience)

	req, err := http.NewRequestWithContext(ctx, "POST", attestationTokenURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create attestation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request attestation token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read attestation token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("attestation service returned status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

type EnvClient struct {
	Logger        *zap.Logger
	tokenProvider AttestationTokenProvider
	kmsSigningKey []byte
	serverURL     string
	userAPIURL    string
}

func NewEnvClient(logger *zap.Logger, tokenProvider AttestationTokenProvider, kmsSigningKey []byte, serverURL string, userAPIURL string) *EnvClient {
	return &EnvClient{
		Logger:        logger,
		tokenProvider: tokenProvider,
		kmsSigningKey: kmsSigningKey,
		serverURL:     serverURL,
		userAPIURL:    userAPIURL,
	}
}

func (e *EnvClient) GetEnv(ctx context.Context) ([]byte, error) {
	// Generate RSA key pair on the fly for envelope encryption.
	e.Logger.Sugar().Infow("Generating RSA key pair")
	rsaPrivateKeyPEM, rsaPublicKeyPEM, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Use the RSA public key hash as the attestation nonce.
	rsaKeyHash := crypto.CalculateSignableDigest(crypto.EnvRequestRSAKeyHeader, rsaPublicKeyPEM)
	rsaKeyHashHex := hex.EncodeToString(rsaKeyHash)

	e.Logger.Sugar().Infow("Requesting attestation token")
	jwt, err := e.tokenProvider.GetToken(ctx, types.KMSJWTAudience, rsaKeyHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation token: %w", err)
	}

	e.Logger.Sugar().Debugw("Requesting env from server", "url", e.serverURL)
	response, err := e.sendRequest(ctx, types.EnvRequestV2{
		JWTWithAttestedRSAKey: jwt,
		RSAKeyPEM:             string(rsaPublicKeyPEM),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to request env: %w", err)
	}

	// Verify KMS signature.
	e.Logger.Debug("Verifying response signature")
	isValid, err := crypto.VerifyKMSSignature(*response, e.kmsSigningKey)
	if err != nil {
		return nil, fmt.Errorf("signature verification error: %w", err)
	}
	if !isValid {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decrypt response.
	e.Logger.Debug("Decrypting response")
	rsaPrivateKey, err := crypto.RSAPrivateKeyFromPEM(rsaPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	envJSONBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(rsaPrivateKey, []byte(response.Data.EncryptedCombinedEnv))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %w", err)
	}

	// Best-effort: post attestation JWT to user API with derived-addresses nonce.
	// (Matches older kms-client behavior; failures here are non-fatal.)
	envVars := make(map[string]string)
	if err := json.Unmarshal(envJSONBytes, &envVars); err != nil {
		return nil, fmt.Errorf("failed to unmarshal env JSON: %w", err)
	}

	evmAddresses, solanaAddresses, err := crypto.DeriveAddressesFromMnemonic(envVars[types.MnemonicEnvVarName], types.NumAddressesToDerive)
	if err != nil {
		return nil, fmt.Errorf("failed to derive addresses from mnemonic: %w", err)
	}

	addresses := types.AddressesResponseV1{
		EVMAddresses:    evmAddresses,
		SolanaAddresses: solanaAddresses,
	}
	addressBytes, err := json.Marshal(addresses)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal derived addresses: %w", err)
	}
	e.Logger.Sugar().Infow("Derived addresses from mnemonic", "addresses", string(addressBytes))

	addressesNonce := crypto.CalculateSignableDigest(crypto.AppDerivedAddressesHeader, addressBytes)
	uploadJWT, err := e.tokenProvider.GetToken(ctx, types.DashboardJWTAudience, hex.EncodeToString(addressesNonce))
	if err != nil {
		e.Logger.Sugar().Errorw("Failed to get attestation token for user API", "error", err)
	} else {
		e.Logger.Sugar().Infow("Posting JWT to user API", "url", e.userAPIURL)
		if err := e.postJWTToUserAPI(ctx, uploadJWT); err != nil {
			e.Logger.Sugar().Errorw("Failed to post JWT to user API after retries", "error", err)
		} else {
			e.Logger.Sugar().Infow("Successfully posted JWT to user API")
		}
	}

	return envJSONBytes, nil
}

func (e *EnvClient) retryHTTPRequest(ctx context.Context, logMessage string, operation func() ([]byte, error)) ([]byte, error) {
	retries := 0
	wrappedOperation := func() ([]byte, error) {
		e.Logger.Sugar().Infow(logMessage, "retries", retries)
		retries++
		return operation()
	}

	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.InitialInterval = initialInterval
	exponentialBackoff.MaxInterval = maxInterval
	exponentialBackoff.Multiplier = multiplier

	return backoff.Retry(
		ctx,
		wrappedOperation,
		backoff.WithBackOff(exponentialBackoff),
		backoff.WithMaxElapsedTime(maxElapsedTime),
	)
}

func (e *EnvClient) sendRequest(ctx context.Context, envRequest types.EnvRequestV2) (*types.SignedResponse[types.EnvResponseV2], error) {
	requestBody, err := json.Marshal(envRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal env request: %w", err)
	}

	url := e.serverURL + "/env/v2"
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

	var signedResponse types.SignedResponse[types.EnvResponseV2]
	if err := json.Unmarshal(responseBody, &signedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &signedResponse, nil
}

func (e *EnvClient) postJWTToUserAPI(ctx context.Context, jwt string) error {
	payload := map[string]string{"jwt": jwt}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JWT payload: %w", err)
	}

	url := e.userAPIURL + "/attestation"
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

		e.Logger.Sugar().Debugw("User API response", "status", resp.StatusCode, "body", string(responseBody))
		return responseBody, nil
	}

	_, err = e.retryHTTPRequest(ctx, "Posting JWT to user API...", operation)
	if err != nil {
		return fmt.Errorf("failed to post JWT after retries: %w", err)
	}
	return nil
}
