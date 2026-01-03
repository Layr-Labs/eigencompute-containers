package vtls

type EnvelopeV1 struct {
	Version string `json:"version"`

	BundleHash string `json:"bundle_hash"` // base64 raw 32 bytes (sha256 of canonical bundle fields)
	RequestID  string `json:"request_id"`  // base64 raw bytes (recommended 16 bytes)

	ClientEphemeralPubKey string `json:"client_ephemeral_pubkey"` // base64 raw 32 bytes (X25519)

	Nonce      string `json:"nonce"`      // base64 raw 12 bytes
	Ciphertext string `json:"ciphertext"` // base64 raw bytes (AES-GCM)
}



