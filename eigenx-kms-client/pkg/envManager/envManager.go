package envManager

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/contractCaller"
	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/types"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"go.uber.org/zap"
)

var (
	JWEAppIDHeader = "x-eigenx-app-id"
)

type EnvManager struct {
	logger         *zap.Logger
	contractCaller contractCaller.IContractCaller
}

func NewEnvManager(logger *zap.Logger, contractCaller contractCaller.IContractCaller) (*EnvManager, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	if contractCaller == nil {
		return nil, fmt.Errorf("contractCaller cannot be nil")
	}
	return &EnvManager{
		logger:         logger,
		contractCaller: contractCaller,
	}, nil
}

// GetEnvironmentForLatestRelease retrieves the environment for the latest release of the app specified in the attestation claims.
// @param ctx the context for the operation.
// @param claims the attestation claims containing the app ID and image digest.
// @returns the public environment variables, the encrypted environment JWE bytes, or an error if the operation fails.
func (em *EnvManager) GetEnvironmentForLatestRelease(ctx context.Context, claims *attestation.AttestationClaims) (types.Env, []byte, error) {
	digest, publicEnv, encryptedEnvBytes, err := em.contractCaller.GetLatestRelease(ctx, claims.AppID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get latest release from contract: %w", err)
	}

	// check authorization
	if err := checkAuthorization(claims, digest); err != nil {
		return nil, nil, fmt.Errorf("authorization check failed: %w", err)
	}

	// Parse encrypted env JWE
	msg, err := jwe.Parse(encryptedEnvBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse encrypted env JWE: %w", err)
	}

	// Validate app ID in protected headers
	var retrievedAppID string
	err = msg.ProtectedHeaders().Get(JWEAppIDHeader, &retrievedAppID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get app id from encrypted env headers: %v", err)
	}

	if !strings.EqualFold(retrievedAppID, claims.AppID) {
		return nil, nil, fmt.Errorf("encrypted env app id mismatch: expected %s, got %s", claims.AppID, retrievedAppID)
	}

	return publicEnv, encryptedEnvBytes, nil
}

func checkAuthorization(claims *attestation.AttestationClaims, expectedDigest [32]byte) error {
	actualDigest, err := hex.DecodeString(strings.TrimPrefix(claims.ImageDigest, "sha256:"))
	if err != nil {
		return fmt.Errorf("failed to decode image digest: %v", err)
	}

	if !bytes.Equal(expectedDigest[:], actualDigest) {
		return fmt.Errorf("image digest mismatch: expected %s, got %s", hex.EncodeToString(expectedDigest[:]), hex.EncodeToString(actualDigest))
	}

	return nil
}
