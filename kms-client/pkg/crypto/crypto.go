package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/Layr-Labs/eigenx-kms-client/pkg/types"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
)

var (
	KMSSignatureHeader     = []byte("COMPUTE_APP_KMS_SIGNATURE_V1")
	EnvRequestRSAKeyHeader = []byte("COMPUTE_APP_ENV_REQUEST_RSA_KEY_V1")
	AppDerivedAddressesHeader = []byte("COMPUTE_APP_DERIVED_ADDRESSES_V1")
)

// GenerateRSAKeyPair generates a 4096-bit RSA private key and public key (both PEM encoded).
func GenerateRSAKeyPair() ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPEM, publicKeyPEM, nil
}

func RSAPrivateKeyFromPEM(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privKey, nil
}

// DecryptWithRSAOAEPAndAES256GCM decrypts compact JWE using RSA-OAEP-256 and A256GCM.
func DecryptWithRSAOAEPAndAES256GCM(keyDecrypter interface{}, encryptedData []byte) ([]byte, error) {
	if jweDecrypter, ok := keyDecrypter.(jwe.KeyDecrypter); ok {
		decryptedData, err := jwe.Decrypt(encryptedData, jwe.WithKey(jwa.RSA_OAEP_256(), jweDecrypter))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
		return decryptedData, nil
	}
	if rsaKey, ok := keyDecrypter.(*rsa.PrivateKey); ok {
		decryptedData, err := jwe.Decrypt(encryptedData, jwe.WithKey(jwa.RSA_OAEP_256(), rsaKey))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
		return decryptedData, nil
	}
	return nil, fmt.Errorf("key decrypter is not a JWE key decrypter or RSA private key")
}

func CalculateSignableDigest(header, data []byte) []byte {
	digest := sha256.New()
	digest.Write(header)
	digest.Write([]byte{0x00}) // separator
	digest.Write(data)
	return digest.Sum(nil)
}

// VerifyKMSSignature verifies the server signature over the JSON-encoded SignedResponse.Data.
func VerifyKMSSignature[T any](signedResponse types.SignedResponse[T], publicKeyPEM []byte) (bool, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return false, fmt.Errorf("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not elliptic curve")
	}

	var parsedSig struct{ R, S *big.Int }
	if _, err = asn1.Unmarshal(signedResponse.Signature, &parsedSig); err != nil {
		return false, fmt.Errorf("asn1.Unmarshal: %w", err)
	}

	payloadJSON, err := json.Marshal(signedResponse.Data)
	if err != nil {
		return false, fmt.Errorf("failed to marshal payload: %w", err)
	}

	digest := CalculateSignableDigest(KMSSignatureHeader, payloadJSON)
	if !ecdsa.Verify(ecKey, digest[:], parsedSig.R, parsedSig.S) {
		return false, nil
	}

	return true, nil
}

func DeriveAddressesFromMnemonic(mnemonic string, count int) ([]types.EVMAddressAndDerivationPath, []types.SolanaAddressAndDerivationPath, error) {
	evmAddresses := make([]types.EVMAddressAndDerivationPath, count)
	solanaAddresses := make([]types.SolanaAddressAndDerivationPath, count)

	evmWallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create EVM wallet from mnemonic: %v", err)
	}

	for i := 0; i < count; i++ {
		evmPath := fmt.Sprintf("m/44'/60'/0'/0/%d", i)
		hdpath := hdwallet.MustParseDerivationPath(evmPath)
		evmAccount, err := evmWallet.Derive(hdpath, false)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive EVM address at index %d: %v", i, err)
		}

		solanaPath := fmt.Sprintf("m/44'/501'/%d'/0'", i)
		solanaWallet, err := GenerateSolanaWalletFromMnemonicSeed(mnemonic, uint32(i))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive Solana address at index %d: %v", i, err)
		}

		evmAddresses[i] = types.EVMAddressAndDerivationPath{
			Address:        evmAccount.Address,
			DerivationPath: evmPath,
		}
		solanaAddresses[i] = types.SolanaAddressAndDerivationPath{
			Address:        solanaWallet.PublicKey().String(),
			DerivationPath: solanaPath,
		}
	}

	return evmAddresses, solanaAddresses, nil
}


