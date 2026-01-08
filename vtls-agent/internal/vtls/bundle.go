package vtls

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	ProtocolVersionV1 = "vtls/1"

	// Domain separation for bundle signatures.
	bundleSigHeaderV1 = "VTLS_BUNDLE_SIG_V1"
)

type BundleV1 struct {
	Version    string `json:"version"`
	AppAddress string `json:"app_address"`
	Domain     string `json:"domain"`
	Origin     string `json:"origin"`

	EncPubKey string `json:"enc_pubkey"` // base64 raw 32 bytes
	SigPubKey string `json:"sig_pubkey"` // base64 compressed 33 bytes

	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	BundleSig string `json:"bundle_sig"` // base64 compact sig (65 bytes)
}

// NewBundleV1 creates a signed vTLS bundle for the given domain/origin.
func NewBundleV1(keys *Keys, domain, origin string, issuedAt time.Time, ttl time.Duration) (*BundleV1, []byte, error) {
	if keys == nil || keys.EncPub == nil || keys.SigPriv == nil || keys.SigPub == nil {
		return nil, nil, fmt.Errorf("missing vTLS keys")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	origin = strings.ToLower(strings.TrimSpace(origin))
	if domain == "" {
		return nil, nil, fmt.Errorf("empty domain")
	}
	if origin == "" {
		return nil, nil, fmt.Errorf("empty origin")
	}

	iat := issuedAt.Unix()
	exp := issuedAt.Add(ttl).Unix()

	encPub := keys.EncPub.Bytes() // 32 bytes for X25519
	sigPubCompressed := keys.SigPub.SerializeCompressed()

	b := &BundleV1{
		Version:    ProtocolVersionV1,
		AppAddress: strings.ToLower(keys.AppAddress),
		Domain:     domain,
		Origin:     origin,
		EncPubKey:  base64.StdEncoding.EncodeToString(encPub),
		SigPubKey:  base64.StdEncoding.EncodeToString(sigPubCompressed),
		IssuedAt:   iat,
		ExpiresAt:  exp,
	}

	signingBytes, err := canonicalBundleSigningBytesV1(b, encPub, sigPubCompressed)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256(signingBytes)

	compactSig, err := signSecp256k1Compact(keys.SigPriv, h[:])
	if err != nil {
		return nil, nil, fmt.Errorf("bundle signature: %w", err)
	}
	b.BundleSig = base64.StdEncoding.EncodeToString(compactSig)

	return b, h[:], nil
}

func canonicalBundleSigningBytesV1(b *BundleV1, encPubRaw32, sigPubCompressed33 []byte) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("nil bundle")
	}
	if b.Version != ProtocolVersionV1 {
		return nil, fmt.Errorf("unexpected bundle version %q", b.Version)
	}
	if len(encPubRaw32) != 32 {
		return nil, fmt.Errorf("unexpected enc pubkey length %d", len(encPubRaw32))
	}
	if len(sigPubCompressed33) != 33 {
		return nil, fmt.Errorf("unexpected sig pubkey length %d", len(sigPubCompressed33))
	}
	var buf bytes.Buffer
	buf.WriteString(bundleSigHeaderV1)
	buf.WriteByte(0x00)

	writeStr0(&buf, b.Version)
	writeStr0(&buf, strings.ToLower(b.AppAddress))
	writeStr0(&buf, strings.ToLower(b.Domain))
	writeStr0(&buf, strings.ToLower(b.Origin))

	buf.Write(encPubRaw32)
	buf.WriteByte(0x00)
	buf.Write(sigPubCompressed33)
	buf.WriteByte(0x00)

	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(b.IssuedAt))
	buf.Write(tmp[:])
	buf.WriteByte(0x00)
	binary.BigEndian.PutUint64(tmp[:], uint64(b.ExpiresAt))
	buf.Write(tmp[:])

	return buf.Bytes(), nil
}

func VerifyBundleSigV1(b *BundleV1) (bool, error) {
	if b == nil {
		return false, fmt.Errorf("nil bundle")
	}
	if b.Version != ProtocolVersionV1 {
		return false, fmt.Errorf("unexpected version %q", b.Version)
	}

	encPub, err := base64.StdEncoding.DecodeString(b.EncPubKey)
	if err != nil {
		return false, fmt.Errorf("enc_pubkey base64: %w", err)
	}
	sigPubBytes, err := base64.StdEncoding.DecodeString(b.SigPubKey)
	if err != nil {
		return false, fmt.Errorf("sig_pubkey base64: %w", err)
	}
	sigPub, err := secp256k1.ParsePubKey(sigPubBytes)
	if err != nil {
		return false, fmt.Errorf("sig_pubkey parse: %w", err)
	}

	signingBytes, err := canonicalBundleSigningBytesV1(b, encPub, sigPubBytes)
	if err != nil {
		return false, err
	}
	h := sha256.Sum256(signingBytes)

	compactSig, err := base64.StdEncoding.DecodeString(b.BundleSig)
	if err != nil {
		return false, fmt.Errorf("bundle_sig base64: %w", err)
	}
	ok, err := verifySecp256k1Compact(sigPub, h[:], compactSig)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func writeStr0(buf *bytes.Buffer, s string) {
	buf.WriteString(s)
	buf.WriteByte(0x00)
}




