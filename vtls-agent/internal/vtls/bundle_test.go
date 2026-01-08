package vtls

import (
	"testing"
	"time"
)

func TestBundleV1_SignAndVerify(t *testing.T) {
	keys, err := DeriveKeysFromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("DeriveKeysFromMnemonic: %v", err)
	}

	now := time.Unix(1734739200, 0) // fixed
	b, _, err := NewBundleV1(keys, "app.example.com", "https://app.example.com", now, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewBundleV1: %v", err)
	}
	if b.BundleSig == "" || b.EncPubKey == "" || b.SigPubKey == "" {
		t.Fatalf("expected bundle to include keys and signature")
	}

	ok, err := VerifyBundleSigV1(b)
	if err != nil {
		t.Fatalf("VerifyBundleSigV1: %v", err)
	}
	if !ok {
		t.Fatalf("expected bundle signature to verify")
	}
}




