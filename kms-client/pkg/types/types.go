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

// EnvRequestV3 represents a V3 request with raw attestation bytes (self-verified)
type EnvRequestV3 struct {
	// Attestation is base64-encoded raw attestation protobuf bytes.
	// The attestation's report data contains a hash of the RSA key, binding them together.
	Attestation string `json:"attestation"`
	// RSAKeyPEM is the RSA public key in PEM format, attested via the nonce in the attestation.
	RSAKeyPEM string `json:"rsaKey"`
}

type EnvResponseV3 struct {
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
