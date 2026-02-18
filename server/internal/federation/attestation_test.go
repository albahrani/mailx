package federation

import (
	"encoding/base64"
	"testing"
)

func TestKeyAttestationPayload_V1Golden(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}

	address := "alice@example.test"
	createdAt := int64(1700000000)
	got := string(KeyAttestationPayload(address, pub, createdAt))

	want := "mailx-key-attestation-v1\n" + address + "\n" + base64.StdEncoding.EncodeToString(pub) + "\n1700000000"
	if got != want {
		t.Fatalf("unexpected payload\n got: %q\nwant: %q", got, want)
	}
}
