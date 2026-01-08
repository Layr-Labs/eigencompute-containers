package vtls

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestAADBinding_RequestDecryptFailsOnPathMismatch(t *testing.T) {
	keys, err := DeriveKeysFromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("DeriveKeysFromMnemonic: %v", err)
	}

	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	clientPub := clientPriv.PublicKey()

	var bundleHash32 [32]byte
	for i := range bundleHash32 {
		bundleHash32[i] = byte(i)
	}
	requestID := []byte("0123456789abcdef")

	key32, err := DeriveSymmetricKeyV1(keys.EncPriv, clientPub, bundleHash32[:])
	if err != nil {
		t.Fatalf("DeriveSymmetricKeyV1: %v", err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}

	plaintext := []byte("hello")
	aad := aadRequestV1("POST", "/api/private", bundleHash32[:], requestID)
	ct, err := aesGCMSeal(key32[:], nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("aesGCMSeal: %v", err)
	}

	// Correct path decrypts.
	pt, err := DecryptRequestV1(key32, "POST", "/api/private", bundleHash32[:], requestID, nonce, ct)
	if err != nil {
		t.Fatalf("DecryptRequestV1 (correct): %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("plaintext mismatch")
	}

	// Wrong path fails.
	if _, err := DecryptRequestV1(key32, "POST", "/api/public", bundleHash32[:], requestID, nonce, ct); err == nil {
		t.Fatalf("expected decrypt failure on path mismatch")
	}
}




