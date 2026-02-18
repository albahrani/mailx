package app

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"

	"github.com/albahrani/mailx/server/internal/crypto"
)

func loadOrGenerateServerSigningKey(keyFile string) (*crypto.SigningKeyPair, error) {
	data, err := os.ReadFile(keyFile)
	if err == nil {
		var keyData struct {
			PublicKey  string `json:"publicKey"`
			PrivateKey string `json:"privateKey"`
		}
		if err := json.Unmarshal(data, &keyData); err == nil {
			privKey, err := base64.StdEncoding.DecodeString(keyData.PrivateKey)
			if err == nil && len(privKey) == crypto.SigningPrivateKeySize {
				pubKey, err := base64.StdEncoding.DecodeString(keyData.PublicKey)
				if err == nil && len(pubKey) == crypto.SigningPublicKeySize {
					return &crypto.SigningKeyPair{PublicKey: pubKey, PrivateKey: privKey}, nil
				}
			}
		}
	}

	log.Println("Generating new server signing key pair...")
	kp, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		return nil, err
	}

	keyData := struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}{
		PublicKey:  base64.StdEncoding.EncodeToString(kp.PublicKey),
		PrivateKey: base64.StdEncoding.EncodeToString(kp.PrivateKey),
	}

	data, err = json.MarshalIndent(keyData, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, data, 0600); err != nil {
		return nil, err
	}

	log.Printf("Server signing key saved to %s", keyFile)
	return kp, nil
}

func loadOrGenerateServerKey(keyFile string) (*crypto.KeyPair, error) {
	data, err := os.ReadFile(keyFile)
	if err == nil {
		var keyData struct {
			PublicKey  string `json:"publicKey"`
			PrivateKey string `json:"privateKey"`
		}
		if err := json.Unmarshal(data, &keyData); err == nil {
			privKey, err := base64.StdEncoding.DecodeString(keyData.PrivateKey)
			if err == nil && len(privKey) == crypto.PrivateKeySize {
				pubKey, err := base64.StdEncoding.DecodeString(keyData.PublicKey)
				if err == nil && len(pubKey) == crypto.PublicKeySize {
					return &crypto.KeyPair{PublicKey: pubKey, PrivateKey: privKey}, nil
				}
			}
		}
	}

	log.Println("Generating new server key pair...")
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	keyData := struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}{
		PublicKey:  base64.StdEncoding.EncodeToString(kp.PublicKey),
		PrivateKey: base64.StdEncoding.EncodeToString(kp.PrivateKey),
	}

	data, err = json.MarshalIndent(keyData, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, data, 0600); err != nil {
		return nil, err
	}

	log.Printf("Server key saved to %s", keyFile)
	log.Printf("Public key: %s", keyData.PublicKey)
	return kp, nil
}
