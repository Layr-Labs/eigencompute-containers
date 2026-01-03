package vtls

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func signSecp256k1Compact(priv *secp256k1.PrivateKey, msgHash32 []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("nil private key")
	}
	if len(msgHash32) != 32 {
		return nil, fmt.Errorf("expected 32-byte message hash, got %d", len(msgHash32))
	}
	return secp256k1ecdsa.SignCompact(priv, msgHash32, false), nil
}

func verifySecp256k1Compact(pub *secp256k1.PublicKey, msgHash32 []byte, compactSig []byte) (bool, error) {
	if pub == nil {
		return false, fmt.Errorf("nil public key")
	}
	if len(msgHash32) != 32 {
		return false, fmt.Errorf("expected 32-byte message hash, got %d", len(msgHash32))
	}
	// RecoverCompact verifies the signature and returns the recovered public key.
	recovered, wasCompressed, err := secp256k1ecdsa.RecoverCompact(compactSig, msgHash32)
	if err != nil {
		return false, nil
	}
	_ = wasCompressed
	return recovered.IsEqual(pub), nil
}

// SignCompactDigestV1 signs a 32-byte digest with secp256k1 and returns a compact (recoverable) signature.
//
// The output is 65 bytes and is suitable for base64 encoding.
func SignCompactDigestV1(priv *secp256k1.PrivateKey, digest32 []byte) ([]byte, error) {
	return signSecp256k1Compact(priv, digest32)
}


