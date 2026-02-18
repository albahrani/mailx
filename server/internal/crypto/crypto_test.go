package crypto

import "testing"

func TestGenerateKeyPair_Sizes(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(kp.PublicKey) != PublicKeySize {
		t.Fatalf("public key size: got %d want %d", len(kp.PublicKey), PublicKeySize)
	}
	if len(kp.PrivateKey) != PrivateKeySize {
		t.Fatalf("private key size: got %d want %d", len(kp.PrivateKey), PrivateKeySize)
	}
}

func TestSigningKeyPair_SignVerify(t *testing.T) {
	kp, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair: %v", err)
	}
	msg := []byte("hello")
	sig := kp.Sign(msg)
	if !VerifySignature(kp.PublicKey, msg, sig) {
		t.Fatalf("signature verification failed")
	}
	if VerifySignature(kp.PublicKey, []byte("tampered"), sig) {
		t.Fatalf("expected verification to fail for tampered message")
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

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	sender, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(sender): %v", err)
	}
	recipient, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(recipient): %v", err)
	}

	pt := []byte("test message")
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

func TestDecrypt_FailsWithWrongNonce(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()

	ct, nonce, err := EncryptMessage([]byte("msg"), recipient.PublicKey, sender.PrivateKey)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	nonce[0] ^= 0xFF
	if _, err := DecryptMessage(ct, nonce, sender.PublicKey, recipient.PrivateKey); err == nil {
		t.Fatalf("expected decryption error")
	}
}
