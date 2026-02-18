package federation

import (
	"encoding/base64"
	"strconv"
)

// KeyAttestationPayload returns the canonical bytes a server signs to attest a
// user's encryption public key.
//
// Format (v1):
//
//	mailx-key-attestation-v1\n<address>\n<b64(publicKey)>\n<createdAtUnix>
func KeyAttestationPayload(address string, publicKey []byte, createdAtUnix int64) []byte {
	b64 := base64.StdEncoding.EncodeToString(publicKey)
	created := strconv.FormatInt(createdAtUnix, 10)
	return []byte("mailx-key-attestation-v1\n" + address + "\n" + b64 + "\n" + created)
}
