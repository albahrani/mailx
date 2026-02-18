package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/albahrani/mailx/server/internal/crypto"
	"github.com/albahrani/mailx/server/internal/federation"
	pb "github.com/albahrani/mailx/server/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{
		Domain:         "example.test",
		GRPCPort:       "0",
		HTTPPort:       "0",
		DatabasePath:   filepath.Join(dir, "test.db"),
		ServerKeyFile:  filepath.Join(dir, "server_key.json"),
		MaxMessageSize: 1024 * 1024,
		DefaultQuota:   1024,
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newBufconnClient(t *testing.T, srv *Server) (*grpc.ClientConn, pb.ClientServiceClient) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	srv.RegisterGRPC(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		_ = lis.Close()
	})

	dialer := func(ctx context.Context, _ string) (net.Conn, error) { return lis.Dial() }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, pb.NewClientServiceClient(conn)
}

func TestLoadOrGenerateServerKey_Persists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")
	k1, err := loadOrGenerateServerKey(path)
	if err != nil {
		t.Fatalf("loadOrGenerateServerKey: %v", err)
	}
	k2, err := loadOrGenerateServerKey(path)
	if err != nil {
		t.Fatalf("loadOrGenerateServerKey(2): %v", err)
	}
	if string(k1.PublicKey) != string(k2.PublicKey) || string(k1.PrivateKey) != string(k2.PrivateKey) {
		t.Fatalf("expected same key material")
	}
}

func TestLoadOrGenerateServerSigningKey_Persists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.sign.json")
	k1, err := loadOrGenerateServerSigningKey(path)
	if err != nil {
		t.Fatalf("loadOrGenerateServerSigningKey: %v", err)
	}
	k2, err := loadOrGenerateServerSigningKey(path)
	if err != nil {
		t.Fatalf("loadOrGenerateServerSigningKey(2): %v", err)
	}
	if string(k1.PublicKey) != string(k2.PublicKey) || string(k1.PrivateKey) != string(k2.PrivateKey) {
		t.Fatalf("expected same signing key material")
	}
}

func TestWellKnownHandler_ResponseShape(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/mailx-server", nil)
	rr := httptest.NewRecorder()
	s.WellKnownHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d", rr.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body["domain"] != s.config.Domain {
		t.Fatalf("domain mismatch")
	}
	if _, ok := body["signKey"].(string); !ok {
		t.Fatalf("missing signKey")
	}
}

func TestAuthAndMessagingFlow_LocalDeliveryAndAccept(t *testing.T) {
	srv := newTestServer(t)
	_, c := newBufconnClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	aliceKP, _ := crypto.GenerateKeyPair()
	bobKP, _ := crypto.GenerateKeyPair()
	if _, err := c.Register(ctx, &pb.RegisterRequest{Username: "alice", Password: "pw", PublicKey: aliceKP.PublicKey}); err != nil {
		t.Fatalf("Register(alice): %v", err)
	}
	if _, err := c.Register(ctx, &pb.RegisterRequest{Username: "bob", Password: "pw", PublicKey: bobKP.PublicKey}); err != nil {
		t.Fatalf("Register(bob): %v", err)
	}

	aliceLogin, err := c.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw"})
	if err != nil {
		t.Fatalf("Login(alice): %v", err)
	}
	bobLogin, err := c.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "pw"})
	if err != nil {
		t.Fatalf("Login(bob): %v", err)
	}

	sendResp, err := c.SendMessage(ctx, &pb.SendMessageRequest{
		AccessToken:      aliceLogin.AccessToken,
		Recipients:       []string{"bob@example.test"},
		EncryptedMessage: []byte("cipher"),
		Metadata:         &pb.MessageMetadata{Timestamp: time.Now().Unix(), Size: 6, Subject: "hello"},
	})
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if sendResp.MessageId == "" {
		t.Fatalf("expected message id")
	}

	listResp, err := c.ListMessages(ctx, &pb.ListMessagesRequest{AccessToken: bobLogin.AccessToken, Folder: "requests", Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("ListMessages(requests): %v", err)
	}
	if listResp.TotalCount != 1 || len(listResp.Messages) != 1 {
		t.Fatalf("unexpected requests counts: %d/%d", listResp.TotalCount, len(listResp.Messages))
	}
	msgID := listResp.Messages[0].MessageId

	getResp, err := c.GetMessage(ctx, &pb.GetMessageRequest{AccessToken: bobLogin.AccessToken, MessageId: msgID})
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if string(getResp.EncryptedMessage) != "cipher" {
		t.Fatalf("encrypted mismatch")
	}

	if _, err := c.AcceptContact(ctx, &pb.AcceptContactRequest{AccessToken: bobLogin.AccessToken, Address: "alice@example.test"}); err != nil {
		t.Fatalf("AcceptContact: %v", err)
	}
	listInbox, err := c.ListMessages(ctx, &pb.ListMessagesRequest{AccessToken: bobLogin.AccessToken, Folder: "inbox", Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("ListMessages(inbox): %v", err)
	}
	if listInbox.TotalCount != 1 {
		t.Fatalf("expected 1 message in inbox")
	}
}

func TestLogin_InvalidPassword(t *testing.T) {
	srv := newTestServer(t)
	_, c := newBufconnClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	kp, _ := crypto.GenerateKeyPair()
	if _, err := c.Register(ctx, &pb.RegisterRequest{Username: "alice", Password: "pw", PublicKey: kp.PublicKey}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, err := c.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "wrong"})
	st, _ := status.FromError(err)
	if st == nil || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestSendMessage_InvalidToken(t *testing.T) {
	srv := newTestServer(t)
	_, c := newBufconnClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.SendMessage(ctx, &pb.SendMessageRequest{AccessToken: "bad", Recipients: []string{"bob@example.test"}, EncryptedMessage: []byte("cipher"), Metadata: &pb.MessageMetadata{Timestamp: time.Now().Unix(), Size: 6, Subject: "hello"}})
	st, _ := status.FromError(err)
	if st == nil || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestGetContactKey_InvalidAddress(t *testing.T) {
	srv := newTestServer(t)
	_, c := newBufconnClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.GetContactKey(ctx, &pb.GetContactKeyRequest{AccessToken: "", Address: "not-an-address"})
	st, _ := status.FromError(err)
	if st == nil || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestGetContactKey_VerifiesServerSignature(t *testing.T) {
	srv := newTestServer(t)
	_, c := newBufconnClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	kp, _ := crypto.GenerateKeyPair()
	if _, err := c.Register(ctx, &pb.RegisterRequest{Username: "alice", Password: "pw", PublicKey: kp.PublicKey}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	login, err := c.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	resp, err := c.GetContactKey(ctx, &pb.GetContactKeyRequest{AccessToken: login.AccessToken, Address: "alice@example.test"})
	if err != nil {
		t.Fatalf("GetContactKey: %v", err)
	}
	payload := federation.KeyAttestationPayload(resp.Address, resp.PublicKey, resp.CreatedAt)
	if !crypto.VerifySignature(srv.SigningPublicKey(), payload, resp.ServerSignature) {
		t.Fatalf("expected attestation signature to verify")
	}
}

func TestValidateToken_Errors(t *testing.T) {
	s := newTestServer(t)
	if _, err := s.validateToken("not-base64"); err == nil {
		t.Fatalf("expected error")
	}
	if _, err := s.validateToken(base64.StdEncoding.EncodeToString([]byte("no-colon"))); err == nil {
		t.Fatalf("expected error")
	}
	expired := base64.StdEncoding.EncodeToString([]byte("u1:" + "1"))
	if _, err := s.validateToken(expired); err == nil {
		t.Fatalf("expected expired error")
	}
}

func TestRegister_InvalidArgs(t *testing.T) {
	srv := newTestServer(t)
	_, c := newBufconnClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.Register(ctx, &pb.RegisterRequest{Username: "", Password: "pw", PublicKey: make([]byte, crypto.PublicKeySize)})
	if err == nil {
		t.Fatalf("expected error")
	}
	if _, ok := status.FromError(err); !ok {
		t.Fatalf("expected gRPC status error")
	}
}
