package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	clientcrypto "github.com/albahrani/mailx/client/internal/crypto"
	pb "github.com/albahrani/mailx/client/proto"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/grpc"
)

func TestClient_Login_NotConnected(t *testing.T) {
	c := &Client{config: &ClientConfig{Username: "alice"}}
	if err := c.Login("pw"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestClient_SendMessage_NotConnected(t *testing.T) {
	c := &Client{config: &ClientConfig{AccessToken: "t"}}
	if err := c.SendMessage("bob@example.test", "s", "b"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestClient_SendMessage_NotLoggedIn(t *testing.T) {
	c := &Client{config: &ClientConfig{}, client: &mockClientService{}}
	if err := c.SendMessage("bob@example.test", "s", "b"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestClient_SendMessage_Success_EncryptsPayload(t *testing.T) {
	// Client's own encryption key pair.
	senderKP, err := clientcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(sender): %v", err)
	}

	// Recipient encryption keys (what GetContactKey returns).
	recipientKP, err := clientcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(recipient): %v", err)
	}

	// Domain signing key (for key attestation).
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(sign): %v", err)
	}

	createdAt := time.Now().Add(-1 * time.Minute).Unix()
	recipientAddr := "bob@example.test"
	payload := keyAttestationPayload(recipientAddr, recipientKP.PublicKey, createdAt)
	sig := ed25519.Sign(signPriv, payload)

	var gotSend *pb.SendMessageRequest
	m := &mockClientService{}
	m.getContactKey = func(ctx context.Context, in *pb.GetContactKeyRequest, _ ...grpc.CallOption) (*pb.GetContactKeyResponse, error) {
		return &pb.GetContactKeyResponse{
			Address:         recipientAddr,
			PublicKey:       recipientKP.PublicKey,
			ServerSignature: sig,
			CreatedAt:       createdAt,
		}, nil
	}
	m.sendMessage = func(ctx context.Context, in *pb.SendMessageRequest, _ ...grpc.CallOption) (*pb.SendMessageResponse, error) {
		gotSend = in
		return &pb.SendMessageResponse{MessageId: "m1", Timestamp: time.Now().Unix(), DeliveryStatuses: []*pb.DeliveryStatus{{Recipient: recipientAddr, Status: pb.DeliveryStatus_DELIVERED}}}, nil
	}

	c := &Client{
		config: &ClientConfig{AccessToken: "t"},
		client: m,
		keyPair: &clientcrypto.KeyPair{
			PublicKey:  senderKP.PublicKey,
			PrivateKey: senderKP.PrivateKey,
		},
		signKeyCache: map[string][]byte{"example.test": signPub},
	}

	subject := "hello"
	body := "world"
	if err := c.SendMessage(recipientAddr, subject, body); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if gotSend == nil {
		t.Fatalf("expected SendMessage RPC")
	}
	if gotSend.AccessToken != "t" {
		t.Fatalf("access token mismatch")
	}
	if len(gotSend.Recipients) != 1 || gotSend.Recipients[0] != recipientAddr {
		t.Fatalf("recipients mismatch")
	}
	if gotSend.Metadata == nil || gotSend.Metadata.Subject != subject {
		t.Fatalf("metadata missing/subject mismatch")
	}
	if gotSend.Metadata.Size != int32(len(gotSend.EncryptedMessage)) {
		t.Fatalf("metadata size mismatch")
	}

	// Verify blob format and that it decrypts to expected JSON payload.
	var blob map[string]any
	if err := json.Unmarshal(gotSend.EncryptedMessage, &blob); err != nil {
		t.Fatalf("blob json: %v", err)
	}
	nonceStr, _ := blob["nonce"].(string)
	ctStr, _ := blob["ciphertext"].(string)
	nonce, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil {
		t.Fatalf("nonce b64: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ctStr)
	if err != nil {
		t.Fatalf("ct b64: %v", err)
	}

	pt, err := clientcrypto.DecryptMessage(ct, nonce, senderKP.PublicKey, recipientKP.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	var msg map[string]any
	if err := json.Unmarshal(pt, &msg); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	if msg["subject"] != subject || msg["body"] != body {
		t.Fatalf("payload mismatch: %#v", msg)
	}
}

func TestClient_SendMessage_InvalidKeyAttestationSignature(t *testing.T) {
	senderKP, _ := clientcrypto.GenerateKeyPair()
	recipientKP, _ := clientcrypto.GenerateKeyPair()
	signPub, _, _ := ed25519.GenerateKey(rand.Reader)

	createdAt := time.Now().Unix()
	recipientAddr := "bob@example.test"

	m := &mockClientService{}
	m.getContactKey = func(ctx context.Context, in *pb.GetContactKeyRequest, _ ...grpc.CallOption) (*pb.GetContactKeyResponse, error) {
		return &pb.GetContactKeyResponse{Address: recipientAddr, PublicKey: recipientKP.PublicKey, ServerSignature: []byte("bad"), CreatedAt: createdAt}, nil
	}
	m.sendMessage = func(ctx context.Context, in *pb.SendMessageRequest, _ ...grpc.CallOption) (*pb.SendMessageResponse, error) {
		return nil, errors.New("should not be called")
	}

	c := &Client{config: &ClientConfig{AccessToken: "t"}, client: m, keyPair: senderKP, signKeyCache: map[string][]byte{"example.test": signPub}}
	err := c.SendMessage(recipientAddr, "s", "b")
	if err == nil || !strings.Contains(err.Error(), "attestation") {
		t.Fatalf("expected attestation error, got %v", err)
	}
}

func TestClient_ReadMessage_Success_DecryptsPayload(t *testing.T) {
	recipientKP, _ := clientcrypto.GenerateKeyPair()
	senderKP, _ := clientcrypto.GenerateKeyPair()
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	createdAt := time.Now().Add(-1 * time.Minute).Unix()
	senderAddr := "alice@example.test"

	// Prepare encrypted message blob like server stores.
	plain, _ := json.Marshal(map[string]any{"subject": "sub", "body": "body", "timestamp": time.Now().Format(time.RFC3339)})
	ct, nonce, err := clientcrypto.EncryptMessage(plain, recipientKP.PublicKey, senderKP.PrivateKey)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	blobJSON, _ := json.Marshal(map[string]any{"nonce": base64.StdEncoding.EncodeToString(nonce), "ciphertext": base64.StdEncoding.EncodeToString(ct)})

	// Sender key attestation signature.
	payload := keyAttestationPayload(senderAddr, senderKP.PublicKey, createdAt)
	sig := ed25519.Sign(signPriv, payload)

	m := &mockClientService{}
	m.getMessage = func(ctx context.Context, in *pb.GetMessageRequest, _ ...grpc.CallOption) (*pb.GetMessageResponse, error) {
		return &pb.GetMessageResponse{MessageId: in.MessageId, Sender: senderAddr, EncryptedMessage: blobJSON}, nil
	}
	m.getContactKey = func(ctx context.Context, in *pb.GetContactKeyRequest, _ ...grpc.CallOption) (*pb.GetContactKeyResponse, error) {
		// ReadMessage asks for sender key.
		return &pb.GetContactKeyResponse{Address: senderAddr, PublicKey: senderKP.PublicKey, ServerSignature: sig, CreatedAt: createdAt}, nil
	}

	c := &Client{config: &ClientConfig{AccessToken: "t"}, client: m, keyPair: recipientKP, signKeyCache: map[string][]byte{"example.test": signPub}}
	if err := c.ReadMessage("m1"); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
}

func TestClient_ReadMessage_InvalidBlobJSON(t *testing.T) {
	recipientKP, _ := clientcrypto.GenerateKeyPair()
	m := &mockClientService{}
	m.getMessage = func(ctx context.Context, in *pb.GetMessageRequest, _ ...grpc.CallOption) (*pb.GetMessageResponse, error) {
		return &pb.GetMessageResponse{MessageId: in.MessageId, Sender: "alice@example.test", EncryptedMessage: []byte("not-json")}, nil
	}

	c := &Client{config: &ClientConfig{AccessToken: "t"}, client: m, keyPair: recipientKP}
	err := c.ReadMessage("m1")
	if err == nil || !strings.Contains(err.Error(), "message blob") {
		t.Fatalf("expected message blob error, got %v", err)
	}
}
