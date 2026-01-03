package vtls

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

const respSigHeaderV1 = "VTLS_RESPONSE_SIG_V1"

// ResponseSignatureDigestV1 returns the 32-byte digest that is signed for X-VTLS-Signature.
//
// Canonical bytes:
//   "VTLS_RESPONSE_SIG_V1" || 0x00 ||
//   sha256(ciphertext) || 0x00 ||
//   status_code_u32be || 0x00 ||
//   method || 0x00 || path || 0x00 ||
//   bundle_hash(32) || 0x00 || request_id(bytes)
func ResponseSignatureDigestV1(ciphertext []byte, status int, method, path string, bundleHash32, requestID []byte) [32]byte {
	ctHash := sha256.Sum256(ciphertext)

	var buf bytes.Buffer
	buf.WriteString(respSigHeaderV1)
	buf.WriteByte(0x00)
	buf.Write(ctHash[:])
	buf.WriteByte(0x00)

	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(status))
	buf.Write(tmp[:])
	buf.WriteByte(0x00)

	buf.WriteString(method)
	buf.WriteByte(0x00)
	buf.WriteString(path)
	buf.WriteByte(0x00)

	buf.Write(bundleHash32)
	buf.WriteByte(0x00)
	buf.Write(requestID)

	return sha256.Sum256(buf.Bytes())
}



