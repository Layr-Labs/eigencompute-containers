package vtls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

const (
	kdfInfoV1 = "vtls/1"
)

func DeriveSymmetricKeyV1(encPriv *ecdh.PrivateKey, clientEphemeralPub *ecdh.PublicKey, bundleHash32 []byte) ([32]byte, error) {
	var out [32]byte
	if encPriv == nil || clientEphemeralPub == nil {
		return out, fmt.Errorf("missing X25519 keys")
	}
	if len(bundleHash32) != 32 {
		return out, fmt.Errorf("expected 32-byte bundle_hash, got %d", len(bundleHash32))
	}
	shared, err := encPriv.ECDH(clientEphemeralPub)
	if err != nil {
		return out, fmt.Errorf("x25519 ecdh: %w", err)
	}
	rd := hkdf.New(sha256.New, shared, bundleHash32, []byte(kdfInfoV1))
	_, _ = rd.Read(out[:])
	return out, nil
}

func DecryptRequestV1(key32 [32]byte, method, path string, bundleHash32, requestID []byte, nonce12, ciphertext []byte) ([]byte, error) {
	aad := aadRequestV1(method, path, bundleHash32, requestID)
	return aesGCMOpen(key32[:], nonce12, ciphertext, aad)
}

func EncryptResponseV1(key32 [32]byte, status int, method, path string, bundleHash32, requestID []byte, plaintext []byte) (nonce12 []byte, ciphertext []byte, err error) {
	nonce12 = make([]byte, 12)
	if _, err := rand.Read(nonce12); err != nil {
		return nil, nil, fmt.Errorf("rand nonce: %w", err)
	}
	aad := aadResponseV1(status, method, path, bundleHash32, requestID)
	ct, err := aesGCMSeal(key32[:], nonce12, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return nonce12, ct, nil
}

func aesGCMOpen(key, nonce12, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aes key must be 32 bytes, got %d", len(key))
	}
	if len(nonce12) != 12 {
		return nil, fmt.Errorf("gcm nonce must be 12 bytes, got %d", len(nonce12))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce12, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return pt, nil
}

func aesGCMSeal(key, nonce12, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aes key must be 32 bytes, got %d", len(key))
	}
	if len(nonce12) != 12 {
		return nil, fmt.Errorf("gcm nonce must be 12 bytes, got %d", len(nonce12))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce12, plaintext, aad), nil
}

func aadRequestV1(method, path string, bundleHash32, requestID []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("vtls/1")
	buf.WriteByte(0x00)
	buf.WriteString("req")
	buf.WriteByte(0x00)
	buf.Write(bundleHash32)
	buf.WriteByte(0x00)
	buf.Write(requestID)
	buf.WriteByte(0x00)
	buf.WriteString(method)
	buf.WriteByte(0x00)
	buf.WriteString(path)
	return buf.Bytes()
}

func aadResponseV1(status int, method, path string, bundleHash32, requestID []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("vtls/1")
	buf.WriteByte(0x00)
	buf.WriteString("resp")
	buf.WriteByte(0x00)
	buf.Write(bundleHash32)
	buf.WriteByte(0x00)
	buf.Write(requestID)
	buf.WriteByte(0x00)
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(status))
	buf.Write(tmp[:])
	buf.WriteByte(0x00)
	buf.WriteString(method)
	buf.WriteByte(0x00)
	buf.WriteString(path)
	return buf.Bytes()
}

func DecodeEnvelopeFieldsV1(env *EnvelopeV1) (bundleHash32, requestID, clientEphPub32, nonce12, ciphertext []byte, err error) {
	if env == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("nil envelope")
	}
	if env.Version != ProtocolVersionV1 {
		return nil, nil, nil, nil, nil, fmt.Errorf("unsupported envelope version %q", env.Version)
	}
	bundleHash32, err = base64.StdEncoding.DecodeString(env.BundleHash)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("bundle_hash base64: %w", err)
	}
	if len(bundleHash32) != 32 {
		return nil, nil, nil, nil, nil, fmt.Errorf("bundle_hash must be 32 bytes, got %d", len(bundleHash32))
	}
	requestID, err = base64.StdEncoding.DecodeString(env.RequestID)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("request_id base64: %w", err)
	}
	clientEphPub32, err = base64.StdEncoding.DecodeString(env.ClientEphemeralPubKey)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("client_ephemeral_pubkey base64: %w", err)
	}
	if len(clientEphPub32) != 32 {
		return nil, nil, nil, nil, nil, fmt.Errorf("client_ephemeral_pubkey must be 32 bytes, got %d", len(clientEphPub32))
	}
	nonce12, err = base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("nonce base64: %w", err)
	}
	if len(nonce12) != 12 {
		return nil, nil, nil, nil, nil, fmt.Errorf("nonce must be 12 bytes, got %d", len(nonce12))
	}
	ciphertext, err = base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("ciphertext base64: %w", err)
	}
	return bundleHash32, requestID, clientEphPub32, nonce12, ciphertext, nil
}


