package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"math/big"

	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/pbkdf2"
)

const Hardened uint32 = 0x80000000

func derive(key []byte, chainCode []byte, segment uint32) ([]byte, []byte) {
	buf := []byte{0}
	buf = append(buf, key...)
	buf = append(buf, big.NewInt(int64(segment)).Bytes()...)

	h := hmac.New(sha512.New, chainCode)
	h.Write(buf)
	I := h.Sum(nil)

	IL := I[:32]
	IR := I[32:]

	return IL, IR
}

func GenerateSolanaWalletFromMnemonicSeed(mnemonic string, index uint32) (*solana.Wallet, error) {
	seed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New)

	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	sum := h.Sum(nil)

	derivedSeed := sum[:32]
	chain := sum[32:]

	// m/44'/501'/index'/0'
	path := []uint32{Hardened + uint32(44), Hardened + uint32(501), Hardened + index, Hardened + uint32(0)}
	for _, segment := range path {
		derivedSeed, chain = derive(derivedSeed, chain, segment)
	}

	key := ed25519.NewKeyFromSeed(derivedSeed)
	wallet, err := solana.WalletFromPrivateKeyBase58(base58.Encode(key))
	if err != nil {
		return nil, err
	}

	return wallet, nil
}

