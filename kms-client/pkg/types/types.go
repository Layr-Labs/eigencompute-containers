package types

import "github.com/ethereum/go-ethereum/common"

const DashboardJWTAudience = "EigenX Dashboard"
const KMSJWTAudience = "EigenX KMS"
const MnemonicEnvVarName = "MNEMONIC"
const NumAddressesToDerive = 5

// SignedResponse is the on-wire response envelope returned by the KMS server.
// Signature is expected to be an ASN.1 DER encoded ECDSA signature.
type SignedResponse[T any] struct {
	Data      T      `json:"data"`
	Signature []byte `json:"signature"`
}

// EnvRequestV2 is the request payload for the KMS server /env/v2 endpoint.
type EnvRequestV2 struct {
	JWTWithAttestedRSAKey string `json:"jwtWithAttestedRsaKey"`
	RSAKeyPEM             string `json:"rsaKey"`
}

// EnvResponseV2 is the response payload contained in SignedResponse.Data for /env/v2.
type EnvResponseV2 struct {
	EncryptedCombinedEnv string `json:"encryptedCombinedEnv"`
}

type EVMAddressAndDerivationPath struct {
	Address        common.Address `json:"address" swaggertype:"string" example:"0x1234567890abcdef1234567890abcdef12345678"`
	DerivationPath string         `json:"derivationPath"`
}

type SolanaAddressAndDerivationPath struct {
	Address        string `json:"address"`
	DerivationPath string `json:"derivationPath"`
}

type AddressesResponseV1 struct {
	EVMAddresses    []EVMAddressAndDerivationPath    `json:"evmAddresses"`
	SolanaAddresses []SolanaAddressAndDerivationPath `json:"solanaAddresses"`
}

// EnvRequestV3 is the request payload for the KMS server /env/v3 endpoint.
// V3 uses raw attestation bytes (base64-encoded) instead of a JWT.
// The attestation's report data contains a hash of the RSA key, binding them together.
type EnvRequestV3 struct {
	Attestation string `json:"attestation"`
	RSAKeyPEM   string `json:"rsaKey"`
}

// EnvResponseV3 is the response payload contained in SignedResponse.Data for /env/v3.
type EnvResponseV3 struct {
	EncryptedCombinedEnv string `json:"encryptedCombinedEnv"`
}

// AttestRequest is the request payload for the KMS server /auth/attest endpoint.
type AttestRequest struct {
	Version                int    `json:"version"`
	EncryptedJWTWithRSAKey string `json:"encryptedJWTWithRSAKey,omitempty"`
	JWTWithAttestedRSAKey  string `json:"jwtWithAttestedRsaKey,omitempty"`
	Attestation            string `json:"attestation,omitempty"`
	RSAKeyPEM              string `json:"rsaKey,omitempty"`
}

// AttestResponse is the response payload for the KMS server /auth/attest endpoint.
type AttestResponse struct {
	Token string `json:"token"`
}


