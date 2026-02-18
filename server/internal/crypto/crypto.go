package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	// PublicKeySize is the size of NaCl box (X25519) public keys.
	PublicKeySize = 32
	// PrivateKeySize is the size of NaCl box (X25519) private keys.
	PrivateKeySize = 32
	// NonceSize is the size of NaCl box nonces
	NonceSize = 24

	// SigningPublicKeySize is the size of Ed25519 public keys.
	SigningPublicKeySize = ed25519.PublicKeySize
	// SigningPrivateKeySize is the size of Ed25519 private keys.
	SigningPrivateKeySize = ed25519.PrivateKeySize
	// SigningSignatureSize is the size of Ed25519 signatures.
	SigningSignatureSize = ed25519.SignatureSize
)

// KeyPair represents a NaCl box (X25519) key pair.
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// SigningKeyPair represents an Ed25519 signing key pair.
type SigningKeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair generates a new NaCl box key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &KeyPair{
		PublicKey:  pub[:],
		PrivateKey: priv[:],
	}, nil
}

// GenerateSigningKeyPair generates a new Ed25519 signing key pair.
func GenerateSigningKeyPair() (*SigningKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key pair: %w", err)
	}
	return &SigningKeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// Sign signs a message with the signing private key.
func (kp *SigningKeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(kp.PrivateKey, message)
}

// VerifySignature verifies a signature with an Ed25519 public key.
func VerifySignature(publicKey []byte, message, signature []byte) bool {
	if len(publicKey) != SigningPublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

// EncryptMessage encrypts a message for a recipient using NaCl box
// This is a simplified version for the demo
func EncryptMessage(message []byte, recipientPublicKey, senderPrivateKey []byte) ([]byte, []byte, error) {
	// Generate random nonce
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Convert keys to the right format for NaCl box
	var pubKey [32]byte
	var privKey [32]byte
	copy(pubKey[:], recipientPublicKey)
	copy(privKey[:], senderPrivateKey)

	// Encrypt
	encrypted := box.Seal(nil, message, &nonce, &pubKey, &privKey)

	return encrypted, nonce[:], nil
}

// DecryptMessage decrypts a message using NaCl box
func DecryptMessage(ciphertext, nonce []byte, senderPublicKey, recipientPrivateKey []byte) ([]byte, error) {
	// Convert to fixed-size arrays
	var nonceArray [NonceSize]byte
	var pubKey [32]byte
	var privKey [32]byte

	copy(nonceArray[:], nonce)
	copy(pubKey[:], senderPublicKey)
	copy(privKey[:], recipientPrivateKey)

	// Decrypt
	decrypted, ok := box.Open(nil, ciphertext, &nonceArray, &pubKey, &privKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return decrypted, nil
}

// EncodePublicKey encodes a public key to base64.
func EncodePublicKey(pubKey []byte) string {
	return base64.StdEncoding.EncodeToString(pubKey)
}

// DecodePublicKey decodes a base64 public key.
func DecodePublicKey(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(decoded) != PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: got %d, want %d", len(decoded), PublicKeySize)
	}
	return decoded, nil
}

// HashPassword is a placeholder for password hashing
// In production, use bcrypt or argon2
func HashPassword(password string) string {
	// This is a placeholder - in production use bcrypt
	return password // TODO: Implement proper password hashing
}

// VerifyPassword verifies a password against its hash
func VerifyPassword(password, hash string) bool {
	// Placeholder - in production use bcrypt.CompareHashAndPassword
	return password == hash // TODO: Implement proper password verification
}
