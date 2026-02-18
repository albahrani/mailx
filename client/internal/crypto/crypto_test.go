package crypto

import "testing"

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	sender, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(sender): %v", err)
	}
	recipient, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(recipient): %v", err)
	}

	pt := []byte("hello")
	ct, nonce, err := EncryptMessage(pt, recipient.PublicKey, sender.PrivateKey)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := DecryptMessage(ct, nonce, sender.PublicKey, recipient.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, pt)
	}
}

func TestDecodePublicKey_InvalidSize(t *testing.T) {
	// base64 of 3 bytes, but we require 32.
	if _, err := DecodePublicKey("AQID"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestVerifySignature_InvalidPublicKeySize(t *testing.T) {
	if VerifySignature([]byte{1, 2, 3}, []byte("m"), []byte("s")) {
		t.Fatalf("expected false")
	}
}

func TestEncodeDecodePublicKey_RoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	enc := EncodePublicKey(kp.PublicKey)
	dec, err := DecodePublicKey(enc)
	if err != nil {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	if string(dec) != string(kp.PublicKey) {
		t.Fatalf("public key mismatch")
	}
}

func TestHashVerifyPassword_Placeholder(t *testing.T) {
	h := HashPassword("pw")
	if !VerifyPassword("pw", h) {
		t.Fatalf("expected verify true")
	}
	if VerifyPassword("wrong", h) {
		t.Fatalf("expected verify false")
	}
}
