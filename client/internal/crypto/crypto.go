package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	// PublicKeySize is the size of Ed25519 public keys
	PublicKeySize = ed25519.PublicKeySize // 32 bytes
	// PrivateKeySize is the size of Ed25519 private keys
	PrivateKeySize = ed25519.PrivateKeySize // 64 bytes
	// SignatureSize is the size of Ed25519 signatures
	SignatureSize = ed25519.SignatureSize // 64 bytes
	// NonceSize is the size of NaCl box nonces
	NonceSize = 24
)

// KeyPair represents an Ed25519 key pair
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair generates a new Ed25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// Sign signs a message with the private key
func (kp *KeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(kp.PrivateKey, message)
}

// Verify verifies a signature with the public key
func Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
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
	copy(privKey[:], senderPrivateKey[:32]) // Ed25519 private key first 32 bytes is seed

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
	copy(privKey[:], recipientPrivateKey[:32])

	// Decrypt
	decrypted, ok := box.Open(nil, ciphertext, &nonceArray, &pubKey, &privKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return decrypted, nil
}

// EncodePublicKey encodes a public key to base64
func EncodePublicKey(pubKey ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pubKey)
}

// DecodePublicKey decodes a base64 public key
func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(decoded) != PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: got %d, want %d", len(decoded), PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
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
