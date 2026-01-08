package vtls

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	encInfoV1 = "eigenx/vtls-enc/v1"
	sigInfoV1 = "eigenx/vtls-sig/v1"
)

type Keys struct {
	EncPriv *ecdh.PrivateKey
	EncPub  *ecdh.PublicKey

	SigPriv *secp256k1.PrivateKey
	SigPub  *secp256k1.PublicKey

	// AppAddress is the EVM-style address derived from SigPub (lowercase hex, 0x-prefixed).
	AppAddress string
}

func DeriveKeysFromMnemonic(mnemonic string) (*Keys, error) {
	mnemonic = strings.TrimSpace(mnemonic)
	if mnemonic == "" {
		return nil, fmt.Errorf("MNEMONIC is required")
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("MNEMONIC is not a valid BIP-39 mnemonic")
	}

	seed := bip39.NewSeed(mnemonic, "")

	encSk := hkdfExpand32(seed, []byte(encInfoV1))
	encPriv, err := ecdh.X25519().NewPrivateKey(encSk[:])
	if err != nil {
		return nil, fmt.Errorf("x25519.NewPrivateKey: %w", err)
	}

	sigSk := hkdfExpand32(seed, []byte(sigInfoV1))
	sigPriv := secp256k1.PrivKeyFromBytes(sigSk[:])
	sigPub := sigPriv.PubKey()

	addr, err := evmAddressFromSecp256k1Pub(sigPub)
	if err != nil {
		return nil, err
	}

	return &Keys{
		EncPriv:     encPriv,
		EncPub:      encPriv.PublicKey(),
		SigPriv:     sigPriv,
		SigPub:      sigPub,
		AppAddress:  addr,
	}, nil
}

func hkdfExpand32(seed, info []byte) [32]byte {
	rd := hkdf.New(sha256.New, seed, nil, info) // salt=nil; domain separation via info
	var out [32]byte
	_, _ = rd.Read(out[:])
	return out
}

func evmAddressFromSecp256k1Pub(pub *secp256k1.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("nil secp256k1 public key")
	}
	// Ethereum address = last 20 bytes of keccak256(uncompressed_pubkey[1:])
	uncompressed := pub.SerializeUncompressed() // 65 bytes: 0x04 || X(32) || Y(32)
	if len(uncompressed) != 65 || uncompressed[0] != 0x04 {
		return "", fmt.Errorf("unexpected secp256k1 uncompressed pubkey encoding")
	}

	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(uncompressed[1:])
	sum := h.Sum(nil)
	addr := sum[len(sum)-20:]
	return "0x" + hex.EncodeToString(addr), nil
}




