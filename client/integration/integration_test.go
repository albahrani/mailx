package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	clientcrypto "github.com/albahrani/mailx/client/internal/crypto"
	serverapp "github.com/albahrani/mailx/server/app"
	serverpb "github.com/albahrani/mailx/server/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func newBufconnServer(t *testing.T) (*serverapp.Server, *grpc.Server, *bufconn.Listener) {
	t.Helper()
	dir := t.TempDir()
	cfg := &serverapp.Config{
		Domain:         "example.test",
		GRPCPort:       "0",
		HTTPPort:       "0",
		DatabasePath:   filepath.Join(dir, "test.db"),
		ServerKeyFile:  filepath.Join(dir, "server_key.json"),
		MaxMessageSize: 1024 * 1024,
		DefaultQuota:   1024,
	}

	srv, err := serverapp.NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	srv.RegisterGRPC(gs)
	go func() { _ = gs.Serve(lis) }()

	t.Cleanup(func() {
		gs.Stop()
		_ = lis.Close()
	})

	return srv, gs, lis
}

func dialBufconn(t *testing.T, lis *bufconn.Listener) *grpc.ClientConn {
	t.Helper()
	dialer := func(ctx context.Context, _ string) (net.Conn, error) { return lis.Dial() }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestClientServer_Bufconn_Flow_SendAndRead(t *testing.T) {
	server, _, lis := newBufconnServer(t)
	conn := dialBufconn(t, lis)
	client := serverpb.NewClientServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Register alice and bob.
	aliceKP, _ := clientcrypto.GenerateKeyPair()
	bobKP, _ := clientcrypto.GenerateKeyPair()
	if _, err := client.Register(ctx, &serverpb.RegisterRequest{Username: "alice", Password: "pw", PublicKey: aliceKP.PublicKey}); err != nil {
		t.Fatalf("Register(alice): %v", err)
	}
	if _, err := client.Register(ctx, &serverpb.RegisterRequest{Username: "bob", Password: "pw", PublicKey: bobKP.PublicKey}); err != nil {
		t.Fatalf("Register(bob): %v", err)
	}

	// Login alice and bob.
	aliceLogin, err := client.Login(ctx, &serverpb.LoginRequest{Username: "alice", Password: "pw"})
	if err != nil {
		t.Fatalf("Login(alice): %v", err)
	}
	bobLogin, err := client.Login(ctx, &serverpb.LoginRequest{Username: "bob", Password: "pw"})
	if err != nil {
		t.Fatalf("Login(bob): %v", err)
	}

	// Build a client-side message blob encrypted to bob.
	plain, _ := json.Marshal(map[string]any{"subject": "sub", "body": "hello", "timestamp": time.Now().Format(time.RFC3339)})
	ct, nonce, err := clientcrypto.EncryptMessage(plain, bobKP.PublicKey, aliceKP.PrivateKey)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	blobJSON, _ := json.Marshal(map[string]any{"nonce": base64.StdEncoding.EncodeToString(nonce), "ciphertext": base64.StdEncoding.EncodeToString(ct)})

	// Send message.
	if _, err := client.SendMessage(ctx, &serverpb.SendMessageRequest{
		AccessToken:      aliceLogin.AccessToken,
		Recipients:       []string{"bob@example.test"},
		EncryptedMessage: blobJSON,
		Metadata:         &serverpb.MessageMetadata{Timestamp: time.Now().Unix(), Size: int32(len(blobJSON)), Subject: "sub"},
	}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	// Bob lists requests and fetches the message.
	list, err := client.ListMessages(ctx, &serverpb.ListMessagesRequest{AccessToken: bobLogin.AccessToken, Folder: "requests", Limit: 10})
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(list.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(list.Messages))
	}
	msgID := list.Messages[0].MessageId
	get, err := client.GetMessage(ctx, &serverpb.GetMessageRequest{AccessToken: bobLogin.AccessToken, MessageId: msgID})
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}

	// Verify server attestation for alice key using server's signing pubkey.
	keyResp, err := client.GetContactKey(ctx, &serverpb.GetContactKeyRequest{AccessToken: bobLogin.AccessToken, Address: "alice@example.test"})
	if err != nil {
		t.Fatalf("GetContactKey: %v", err)
	}
	payload := []byte("mailx-key-attestation-v1\n" + keyResp.Address + "\n" + base64.StdEncoding.EncodeToString(keyResp.PublicKey) + "\n" + fmtInt64(keyResp.CreatedAt))
	if !clientcrypto.VerifySignature(server.SigningPublicKey(), payload, keyResp.ServerSignature) {
		t.Fatalf("expected key attestation signature to verify")
	}

	// Decrypt the message as bob.
	var blob map[string]any
	if err := json.Unmarshal(get.EncryptedMessage, &blob); err != nil {
		t.Fatalf("blob json: %v", err)
	}
	nonceStr, _ := blob["nonce"].(string)
	ctStr, _ := blob["ciphertext"].(string)
	n, _ := base64.StdEncoding.DecodeString(nonceStr)
	c, _ := base64.StdEncoding.DecodeString(ctStr)
	pt, err := clientcrypto.DecryptMessage(c, n, aliceKP.PublicKey, bobKP.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	var msg map[string]any
	if err := json.Unmarshal(pt, &msg); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	if msg["body"] != "hello" {
		t.Fatalf("payload mismatch: %v", msg)
	}

	// Accept contact should move requests -> inbox.
	if _, err := client.AcceptContact(ctx, &serverpb.AcceptContactRequest{AccessToken: bobLogin.AccessToken, Address: "alice@example.test"}); err != nil {
		t.Fatalf("AcceptContact: %v", err)
	}
	inbox, err := client.ListMessages(ctx, &serverpb.ListMessagesRequest{AccessToken: bobLogin.AccessToken, Folder: "inbox", Limit: 10})
	if err != nil {
		t.Fatalf("ListMessages(inbox): %v", err)
	}
	if len(inbox.Messages) != 1 {
		t.Fatalf("expected 1 inbox message")
	}
}

func fmtInt64(v int64) string {
	// Avoid strconv import in this file.
	buf := make([]byte, 0, 32)
	neg := v < 0
	if neg {
		v = -v
	}
	if v == 0 {
		buf = append(buf, '0')
	}
	for v > 0 {
		d := v % 10
		buf = append(buf, byte('0'+d))
		v /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
