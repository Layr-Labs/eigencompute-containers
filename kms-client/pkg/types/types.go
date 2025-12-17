package types

const KMSJWTAudience = "EigenX KMS"

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


