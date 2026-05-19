package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

// StorageKeyDST is the domain separation tag for storage encryption key
// derivation. It must stay byte-for-byte identical to the constants in
//   - github.com/Layr-Labs/eigenx-kms (pkg/crypto/storage_key.go)
//   - github.com/Layr-Labs/go-tpm-tools (launcher/internal/storage/key_derivation.go)
//
// All three impls derive the same key from the same mnemonic; any
// divergence would render every PD ever LUKS-formatted with one impl
// unrecoverable by the other. The _V1 suffix exists so a future rotation
// can add a parallel _V2 path without breaking existing PDs.
const StorageKeyDST = "EIGENX_STORAGE_KEY_DERIVATION_V1"

// DeriveStorageKey derives a 256-bit LUKS volume encryption key from a BIP39
// mnemonic. The derivation is intentionally identical to:
//   - github.com/Layr-Labs/eigenx-kms's DeriveStorageKey
//   - the launcher's go-tpm-tools storage.DeriveStorageKey
//
// Algorithm:
//
//  1. BIP39: mnemonic -> 64-byte seed via PBKDF2(mnemonic, "mnemonic", 2048, SHA-512)
//  2. HMAC-SHA256(key=StorageKeyDST, data=seed) -> 32-byte key
//
// Two consumers must derive the same key from the same mnemonic:
//   - The launcher itself, on cold-attach paths where it owns LUKS setup.
//   - The user-container entrypoint script (compute-source-env.sh.tmpl in
//     Layr-Labs/ecloud), on prewarm-detach paths where the launcher defers
//     to it. The script invokes `kms-client derive-storage-key` to obtain
//     the key without re-implementing the crypto in bash — eliminating any
//     risk of cross-impl divergence that would orphan PD data.
//
// The caller is responsible for zeroing the returned key bytes after use.
func DeriveStorageKey(mnemonic string) ([]byte, error) {
	if mnemonic == "" {
		return nil, fmt.Errorf("mnemonic must not be empty")
	}

	// Validate BIP39 word count, wordlist membership, and checksum so an
	// upstream KMS bug that hands us a malformed mnemonic surfaces as an
	// explicit error rather than a silently-wrong key.
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid BIP39 mnemonic")
	}

	seed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New)
	defer ZeroBytes(seed)

	h := hmac.New(sha256.New, []byte(StorageKeyDST))
	h.Write(seed)
	return h.Sum(nil), nil
}

// ZeroBytes overwrites a byte slice with zeros to remove sensitive material
// from memory. Best-effort: the Go compiler/runtime is permitted to copy
// values around, so this is defense-in-depth, not a guarantee.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
