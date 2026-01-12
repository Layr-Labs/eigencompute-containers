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


